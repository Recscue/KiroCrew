"""Unit tests for the pure layer of the sandbox connect fence (issue #9806).

Everything here is syscall-free: BPF bytes, sockaddr decode, and the
fence verdict matrix. The launcher install path and the supervisor loop are
integration-tested on sandbox-capable Linux runners.
"""

from __future__ import annotations

import socket
import struct

import pytest

from kiro_crew.security import connect_fence as cf


def _sockaddr_in(port: int, ip: str) -> bytes:
    return struct.pack("<H", socket.AF_INET) + struct.pack("!H", port) + socket.inet_aton(ip)


def _sockaddr_in6(port: int, ip: str) -> bytes:
    return (
        struct.pack("<H", socket.AF_INET6)
        + struct.pack("!H", port)
        + b"\x00\x00\x00\x00"  # flowinfo
        + socket.inet_pton(socket.AF_INET6, ip)
    )


class TestBpfProgram:
    def test_known_arches_build(self) -> None:
        for machine in ("x86_64", "aarch64"):
            prog = cf.build_connect_notif_prog(machine)
            assert len(prog) == cf.BPF_INSN_COUNT * 8

    def test_unknown_arch_fails_closed_at_build(self) -> None:
        with pytest.raises(cf.FenceUnsupportedArch):
            cf.build_connect_notif_prog("riscv64")

    def test_program_ends_in_allow_and_notif_returns(self) -> None:
        prog = cf.build_connect_notif_prog("x86_64")
        allow = struct.unpack_from("<HBBI", prog, 4 * 8)
        notif = struct.unpack_from("<HBBI", prog, 5 * 8)
        assert allow[3] == cf.SECCOMP_RET_ALLOW
        assert notif[3] == cf.SECCOMP_RET_USER_NOTIF


class TestParseSockaddr:
    def test_ipv4(self) -> None:
        target = cf.parse_sockaddr(_sockaddr_in(22, "127.0.0.1"))
        assert target is not None
        assert (target.family, str(target.address), target.port) == (
            socket.AF_INET,
            "127.0.0.1",
            22,
        )

    def test_ipv6(self) -> None:
        target = cf.parse_sockaddr(_sockaddr_in6(22, "::1"))
        assert target is not None
        assert (target.family, str(target.address), target.port) == (
            socket.AF_INET6,
            "::1",
            22,
        )

    def test_af_unix_is_not_subject_matter(self) -> None:
        raw = struct.pack("<H", socket.AF_UNIX) + b"/tmp/sock\x00"
        assert cf.parse_sockaddr(raw) is None

    def test_truncated_buffers_are_not_subject_matter(self) -> None:
        assert cf.parse_sockaddr(b"") is None
        assert cf.parse_sockaddr(b"\x02") is None
        assert cf.parse_sockaddr(_sockaddr_in(22, "127.0.0.1")[:6]) is None
        assert cf.parse_sockaddr(_sockaddr_in6(22, "::1")[:20]) is None


class TestFenceVerdict:
    SELF = frozenset({"192.0.2.10", "2001:db8::10"})

    def _target(self, raw: bytes) -> cf.ConnectTarget:
        target = cf.parse_sockaddr(raw)
        assert target is not None
        return target

    def test_loopback_v4_port_22_denied(self) -> None:
        assert cf.fence_verdict(self._target(_sockaddr_in(22, "127.0.0.1")), self.SELF)

    def test_loopback_v4_nonstandard_loopback_denied(self) -> None:
        assert cf.fence_verdict(self._target(_sockaddr_in(22, "127.8.9.10")), self.SELF)

    def test_loopback_v6_port_22_denied(self) -> None:
        assert cf.fence_verdict(self._target(_sockaddr_in6(22, "::1")), self.SELF)

    def test_self_adapter_address_denied(self) -> None:
        assert cf.fence_verdict(self._target(_sockaddr_in(22, "192.0.2.10")), self.SELF)

    def test_self_adapter_v6_denied(self) -> None:
        assert cf.fence_verdict(self._target(_sockaddr_in6(22, "2001:db8::10")), self.SELF)

    def test_v4_mapped_v6_folds_onto_v4_identity(self) -> None:
        assert cf.fence_verdict(
            self._target(_sockaddr_in6(22, "::ffff:192.0.2.10")), self.SELF
        )

    def test_foreign_host_port_22_continues(self) -> None:
        assert not cf.fence_verdict(self._target(_sockaddr_in(22, "198.51.100.7")), self.SELF)

    def test_self_address_other_port_continues(self) -> None:
        assert not cf.fence_verdict(self._target(_sockaddr_in(443, "192.0.2.10")), self.SELF)

    def test_loopback_other_port_continues(self) -> None:
        assert not cf.fence_verdict(self._target(_sockaddr_in(8080, "127.0.0.1")), self.SELF)

    def test_none_target_continues(self) -> None:
        assert not cf.fence_verdict(None, self.SELF)


class TestSelfAddressStrings:
    def test_hostnames_dropped_ips_kept(self) -> None:
        got = cf.self_address_strings(["192.0.2.10", "devhost.example", "::1"])
        assert got == frozenset({"192.0.2.10", "::1"})

    def test_v4_mapped_folded(self) -> None:
        got = cf.self_address_strings(["::ffff:192.0.2.10"])
        assert got == frozenset({"192.0.2.10"})

    def test_empty_input_empty_set(self) -> None:
        assert cf.self_address_strings([]) == frozenset()


class TestSupervisorPureParts:
    def test_ioctl_numbers_match_kernel_encoding(self) -> None:
        assert cf.SECCOMP_IOCTL_NOTIF_RECV == 0xC0502100
        assert cf.SECCOMP_IOCTL_NOTIF_SEND == 0xC0182101
        assert cf.SECCOMP_IOCTL_NOTIF_ID_VALID == 0x40082102

    def test_parse_notification_extracts_connect_args(self) -> None:
        buf = bytearray(80)
        struct.pack_into("<QI", buf, 0, 0xAB, 4242)
        # seccomp_data.args live at offset 32; connect ptr=args[1], len=args[2]
        struct.pack_into("<6Q", buf, 32, 3, 0xDEAD0000, 16, 0, 0, 0)
        notif = cf.parse_notification(bytes(buf))
        assert (notif.notif_id, notif.pid) == (0xAB, 4242)
        assert (notif.sockaddr_ptr, notif.sockaddr_len) == (0xDEAD0000, 16)

    def test_parse_notification_caps_runaway_length(self) -> None:
        buf = bytearray(80)
        struct.pack_into("<6Q", buf, 32, 3, 0x1000, 1 << 32, 0, 0, 0)
        assert cf.parse_notification(bytes(buf)).sockaddr_len == 128

    def test_deny_response_is_eperm(self) -> None:
        resp = cf.build_response(7, deny=True)
        notif_id, val, error, flags = struct.unpack("<QqiI", resp)
        assert (notif_id, val, flags) == (7, 0, 0)
        assert error < 0

    def test_continue_response_sets_continue_flag(self) -> None:
        resp = cf.build_response(9, deny=False)
        notif_id, _val, error, flags = struct.unpack("<QqiI", resp)
        assert (notif_id, error) == (9, 0)
        assert flags == cf.SECCOMP_USER_NOTIF_FLAG_CONTINUE

    def test_seccomp_syscall_nr_fails_closed_on_unknown_arch(self) -> None:
        with pytest.raises(cf.FenceUnsupportedArch):
            cf.seccomp_syscall_nr("mips64")
