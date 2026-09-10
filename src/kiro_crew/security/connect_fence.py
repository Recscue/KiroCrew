"""Socket-layer fence for the agent sandbox (issue #9806).

Denies ``connect(2)`` from sandboxed processes to this host's own sshd. The
text tier (``sandbox-escape-ssh-self`` catalog rule + argv floor) refuses the
command lines it can see; this fence closes the residual class the text tier
structurally cannot: interpreter indirection, script bodies, and non-ssh
clients.

Mechanism: a seccomp user-notification filter installed by the sandbox
launcher child. ``connect(2)`` traps to a supervisor in the gateway process,
which decodes the sockaddr and answers deny (``EPERM``) when the target is a
self address on a fenced port, or continue otherwise. Everything in this
module below the ioctl layer is pure and unit-tested; the launcher owns the
install and the fd handoff.

Verdict precedence makes stacking safe: the launcher's existing kill-filter
returns ALLOW for ``connect``, and USER_NOTIF outranks ALLOW, so adding this
filter never weakens the existing one.

Declared limit (also in the PR body): seccomp user-notification sockaddr
inspection carries the documented user-memory race — a multithreaded caller
can rewrite the sockaddr between decode and verdict. The fence raises the
boundary from text-only to socket-layer-with-a-documented-race; full closure
is the netns egress design tracked on issue #9806.
"""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass

# ── Architecture table ──────────────────────────────────────────────────────
# AUDIT_ARCH values and connect(2) syscall numbers for the platforms the
# Linux sandbox backend supports. The BPF program pins BOTH: a filter built
# for the wrong architecture must fail closed at build time, not misread
# syscall numbers at run time.

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

_ARCH_TABLE: dict[str, tuple[int, int]] = {
    # machine -> (audit_arch, __NR_connect)
    "x86_64": (AUDIT_ARCH_X86_64, 42),
    "aarch64": (AUDIT_ARCH_AARCH64, 203),
}


class FenceUnsupportedArch(RuntimeError):
    """Raised when no seccomp arch entry exists for this machine."""


def arch_entry(machine: str) -> tuple[int, int]:
    """Return ``(audit_arch, connect_nr)`` for *machine* or raise."""
    try:
        return _ARCH_TABLE[machine]
    except KeyError as exc:
        raise FenceUnsupportedArch(
            f"connect fence has no seccomp arch entry for {machine!r}"
        ) from exc


# ── BPF program (pure bytes) ────────────────────────────────────────────────
# Layout of struct seccomp_data: nr (offset 0), arch (offset 4),
# instruction_pointer (8), args[0..5] (16 + 8*i).

_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_RET = 0x06
_BPF_K = 0x00

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_USER_NOTIF = 0x7FC00000

_SECCOMP_DATA_NR_OFFSET = 0
_SECCOMP_DATA_ARCH_OFFSET = 4


def _insn(code: int, jt: int, jf: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def build_connect_notif_prog(machine: str) -> bytes:
    """BPF program: trap ``connect`` to user-notif, allow everything else.

    Wrong-arch syscalls are ALLOWED through (they fall to the existing
    kill-filter and the kernel's own arch handling) rather than killed: this
    filter's only job is the connect trap, and returning ALLOW for foreign
    arches keeps it composable with the launcher's deny filter.
    """
    audit_arch, connect_nr = arch_entry(machine)
    return b"".join(
        [
            _insn(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),
            _insn(_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 2, audit_arch),
            _insn(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _SECCOMP_DATA_NR_OFFSET),
            _insn(_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, connect_nr),
            _insn(_BPF_RET | _BPF_K, 0, 0, SECCOMP_RET_ALLOW),
            _insn(_BPF_RET | _BPF_K, 0, 0, SECCOMP_RET_USER_NOTIF),
        ]
    )


BPF_INSN_COUNT = 6


class SockFprog(ctypes.Structure):
    """struct sock_fprog for the seccomp(2) filter install."""

    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_char_p)]


# ── sockaddr decode (pure) ──────────────────────────────────────────────────

_SOCKADDR_IN_LEN = 8  # family + port + addr; trailing pad not required
_SOCKADDR_IN6_MIN_LEN = 24  # family + port + flowinfo + 16-byte addr


@dataclass(frozen=True)
class ConnectTarget:
    family: int
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int


def parse_sockaddr(raw: bytes) -> ConnectTarget | None:
    """Decode an AF_INET/AF_INET6 sockaddr; ``None`` for every other family.

    ``None`` means "not fence subject matter" (AF_UNIX, netlink, truncated
    buffers): the caller must answer CONTINUE, never deny, so a decode gap
    can only ever fail open toward the existing text tier — the fence adds
    denials, it does not invent them.
    """
    if len(raw) < 2:
        return None
    family = struct.unpack_from("<H", raw, 0)[0]
    if family == socket.AF_INET and len(raw) >= _SOCKADDR_IN_LEN:
        port = struct.unpack_from("!H", raw, 2)[0]
        addr = ipaddress.IPv4Address(raw[4:8])
        return ConnectTarget(family, addr, port)
    if family == socket.AF_INET6 and len(raw) >= _SOCKADDR_IN6_MIN_LEN:
        port = struct.unpack_from("!H", raw, 2)[0]
        addr = ipaddress.IPv6Address(raw[8:24])
        return ConnectTarget(family, addr, port)
    return None


# ── Fence policy (pure) ─────────────────────────────────────────────────────

FENCE_PORTS: frozenset[int] = frozenset({22})


def _normalized(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Fold IPv4-mapped IPv6 (::ffff:a.b.c.d) onto its IPv4 identity."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def fence_verdict(
    target: ConnectTarget | None,
    self_addresses: frozenset[str],
    ports: frozenset[int] = FENCE_PORTS,
) -> bool:
    """True to DENY the connect; False to let it continue.

    Denies when the port is fenced AND the address is this host: any
    loopback (127.0.0.0/8, ::1) or any address in *self_addresses* (the
    adapter-sweep set maintained by ``security.host_addresses``). Unparsed
    or non-INET targets always continue — see ``parse_sockaddr``.
    """
    if target is None or target.port not in ports:
        return False
    addr = _normalized(target.address)
    if addr.is_loopback:
        return True
    return str(addr) in self_addresses


def self_address_strings(candidates: list[str]) -> frozenset[str]:
    """Canonicalize the host-address seed into comparable strings.

    Silently drops entries that do not parse as IP literals (hostnames have
    no place at the socket layer) and folds v4-mapped forms, so one set
    serves both families in ``fence_verdict``.
    """
    out: set[str] = set()
    for cand in candidates:
        try:
            addr = ipaddress.ip_address(cand)
        except ValueError:
            continue
        out.add(str(_normalized(addr)))
    return frozenset(out)


# ── OS interface: filter install + supervisor ───────────────────────────────
# Everything above this line is pure; everything below touches the kernel and
# is exercised by the Linux sandbox integration tests, not the unit file.

import errno
import os
import threading

_SYS_SECCOMP_X86_64 = 317
_SYS_SECCOMP_AARCH64 = 277
_SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3

_IOC_WRITE = 1
_IOC_READ = 2
_SECCOMP_IOC_TYPE = 0x21  # '!'

_NOTIF_SIZE = 80  # id(8) pid(4) flags(4) + seccomp_data(64)
_RESP_SIZE = 24  # id(8) val(8) error(4) flags(4)
_ID_SIZE = 8

SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1


def _ioc(direction: int, nr: int, size: int) -> int:
    return (direction << 30) | (size << 16) | (_SECCOMP_IOC_TYPE << 8) | nr


SECCOMP_IOCTL_NOTIF_RECV = _ioc(_IOC_READ | _IOC_WRITE, 0, _NOTIF_SIZE)
SECCOMP_IOCTL_NOTIF_SEND = _ioc(_IOC_READ | _IOC_WRITE, 1, _RESP_SIZE)
SECCOMP_IOCTL_NOTIF_ID_VALID = _ioc(_IOC_WRITE, 2, _ID_SIZE)

_NOTIF_DATA_ARGS_OFFSET = 16 + 16  # notif header (16) + nr/arch/ip (16)


def seccomp_syscall_nr(machine: str) -> int:
    if machine == "x86_64":
        return _SYS_SECCOMP_X86_64
    if machine == "aarch64":
        return _SYS_SECCOMP_AARCH64
    raise FenceUnsupportedArch(
        f"connect fence has no seccomp(2) number for {machine!r}"
    )


def install_connect_filter(machine: str | None = None) -> int:
    """Install the connect-notif filter in THIS process; return the notify fd.

    Called by the sandbox launcher child (which already set no-new-privs for
    the existing filter). Raises ``OSError`` when the kernel lacks user
    notification; the launcher treats that exactly like a failed userns
    probe: warn once, degrade to the text tier, never claim the fence.
    """
    resolved = machine or os.uname().machine
    prog = build_connect_notif_prog(resolved)
    fprog = SockFprog()
    fprog.len = BPF_INSN_COUNT
    fprog.filter = prog
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(
        seccomp_syscall_nr(resolved),
        _SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        ctypes.addressof(fprog),
    )
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "seccomp(SET_MODE_FILTER)")
    return fd


@dataclass(frozen=True)
class Notification:
    """One trapped connect(2), decoded from the RECV buffer."""

    notif_id: int
    pid: int
    sockaddr_ptr: int
    sockaddr_len: int


def parse_notification(buf: bytes) -> Notification:
    """Decode struct seccomp_notif: connect args are ptr=args[1], len=args[2]."""
    notif_id, pid = struct.unpack_from("<QI", buf, 0)
    args = struct.unpack_from("<6Q", buf, _NOTIF_DATA_ARGS_OFFSET)
    return Notification(notif_id, pid, args[1], min(args[2], 128))


def build_response(notif_id: int, deny: bool) -> bytes:
    """struct seccomp_notif_resp: EPERM on deny, CONTINUE otherwise."""
    if deny:
        return struct.pack("<QqiI", notif_id, 0, -errno.EPERM, 0)
    return struct.pack("<QqiI", notif_id, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE)


def _read_target_sockaddr(pid: int, ptr: int, length: int) -> bytes | None:
    """Copy the sockaddr from the trapped process; ``None`` if unreadable.

    The supervisor is the trapped child's sandbox parent, so this read is the
    standard user-notification pattern. An unreadable target answers
    CONTINUE (fail open toward the text tier), matching ``parse_sockaddr``.
    """
    mem_path = os.path.join("/proc", str(pid), "mem")
    try:
        mem_fd = os.open(mem_path, os.O_RDONLY)
    except OSError:
        return None
    try:
        return os.pread(mem_fd, length, ptr)
    except OSError:
        return None
    finally:
        os.close(mem_fd)


def _notif_id_valid(fcntl_mod, notify_fd: int, notif_id: int) -> bool:
    try:
        fcntl_mod.ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, struct.pack("<Q", notif_id))
        return True
    except OSError:
        return False


def supervise(
    notify_fd: int,
    self_addresses: frozenset[str],
    ports: frozenset[int] = FENCE_PORTS,
    on_deny: "Callable[[ConnectTarget | None], None] | None" = None,
) -> None:
    """Answer trapped connects until the notify fd closes (sandbox exit).

    Verdict path per notification: RECV -> copy sockaddr from the target ->
    re-check the notification id is still live (the classic reuse race) ->
    SEND deny-or-continue. Every deny calls *on_deny(target)* so the caller
    can emit the SEL security event without this module importing the event
    log.
    """
    import fcntl

    while True:
        buf = bytearray(_NOTIF_SIZE)
        try:
            fcntl.ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, buf)
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            return  # fd closed: sandbox exited
        notif = parse_notification(bytes(buf))
        raw = _read_target_sockaddr(notif.pid, notif.sockaddr_ptr, notif.sockaddr_len)
        target = parse_sockaddr(raw) if raw is not None else None
        deny = fence_verdict(target, self_addresses, ports)
        if deny and not _notif_id_valid(fcntl, notify_fd, notif.notif_id):
            continue  # the syscall was aborted; nothing to answer
        if deny and on_deny is not None:
            try:
                on_deny(target)
            except Exception:  # noqa: BLE001 - the verdict must still be sent
                pass
        try:
            fcntl.ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, build_response(notif.notif_id, deny))
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.EINTR):
                continue  # target died mid-verdict; keep serving others
            return


def start_supervisor(
    notify_fd: int,
    self_addresses: frozenset[str],
    ports: frozenset[int] = FENCE_PORTS,
    on_deny: "Callable[[ConnectTarget | None], None] | None" = None,
) -> threading.Thread:
    """Run ``supervise`` on a daemon thread owned by the sandbox parent."""
    thread = threading.Thread(
        target=supervise,
        args=(notify_fd, self_addresses, ports, on_deny),
        name="connect-fence-supervisor",
        daemon=True,
    )
    thread.start()
    return thread


# ── Self-address seed (stdlib-only) ─────────────────────────────────────────
# The fence resolves "this host" without importing the text tier's identity
# machinery: the launcher template must stay import-free, and the supervisor
# must never do DNS at connect time. Loopback denial in ``fence_verdict`` is
# unconditional, so this sweep only WIDENS coverage to the host's adapter
# addresses; an empty sweep degrades to loopback-only, never to open.


def fence_self_addresses() -> frozenset[str]:
    """Best-effort adapter-address sweep via stdlib, packet-less.

    Sources, each optional: hostname A/AAAA lookups resolved locally, and a
    UDP-connect probe per family (no packet leaves the host for a datagram
    socket connect; the kernel just picks the egress address).
    """
    candidates: list[str] = []
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    if hostname:
        try:
            for info in socket.getaddrinfo(hostname, None):
                candidates.append(str(info[4][0]).split("%", 1)[0])
        except OSError:
            pass
    for family, probe_target in (
        (socket.AF_INET, ("203.0.113.1", 9)),
        (socket.AF_INET6, ("2001:db8::1", 9)),
    ):
        try:
            probe = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            probe.connect(probe_target)
            candidates.append(str(probe.getsockname()[0]).split("%", 1)[0])
        except OSError:
            pass
        finally:
            probe.close()
    return self_address_strings(candidates)
