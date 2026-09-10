/** Cross-window unread-badge sync: the read side of the relay.
 *
 * `markSlotUnread` reaches every window on its own (each holds a live WS and
 * badges any slot that is not ITS active slot), but `markSlotRead` was purely
 * window-local Redux + localStorage — reading a session in one dashboard
 * window left the bubble lit in every other one. This module carries the read
 * gesture to the gateway (`{type: 'slot_read', slot}`), which rebroadcasts it
 * to every owner window; each dispatches plain `markSlotRead` on receipt.
 *
 * The sender is a module-level indirection bound by `useWebSocket` while
 * mounted, for the same reason `emitSlotFocused` is one: read gestures happen
 * in code (chatSlice's `switchSlot`, the sidebar mark-as-read toggle, the
 * members surface) that has no access to the hook's socket. Before the hook
 * binds (or after it unmounts) the emitter is a no-op — the relay is a
 * best-effort optimization, never load-bearing: the local dispatch it rides
 * beside has already cleared THIS window.
 *
 * Emits are throttled per slot (leading + trailing edge). The arrival-branch
 * caller fires once per streamed row of a watched turn — tool events land
 * several per second — and dropping instead of coalescing would let a
 * final-row emit vanish inside the quiet window, leaving another window's
 * bubble lit until the next event. The trailing send makes the last read of
 * a burst always reach the wire.
 */

const READ_RELAY_QUIET_MS = 1_000

type PendingEntry = { timer: ReturnType<typeof setTimeout>; again: boolean }

let sendSlotReadImpl: (slot: string) => void = () => {}
const pending = new Map<string, PendingEntry>()

/** Bind (or unbind, by passing a no-op) the wire sender. useWebSocket only. */
export function bindSlotReadSender(impl: (slot: string) => void): void {
  sendSlotReadImpl = impl
}

/** Relay "this slot was read here" to every other open dashboard window. */
export function emitSlotRead(slot: string): void {
  if (!slot) return
  const entry = pending.get(slot)
  if (entry) {
    entry.again = true  // coalesce into one trailing send at quiet-window end
    return
  }
  sendSlotReadImpl(slot)
  pending.set(slot, {
    again: false,
    timer: setTimeout(() => {
      const e = pending.get(slot)
      pending.delete(slot)
      // Trailing edge: a read arrived mid-window; send the coalesced one so
      // the LAST read of a burst is never dropped.
      if (e?.again) sendSlotReadImpl(slot)
    }, READ_RELAY_QUIET_MS),
  })
}

/** Flush a slot's pending trailing relay NOW (every slot when omitted).
 *
 * Called when a slot stops being the visible active one (active-slot switch,
 * document hidden). A trailing timer that outlived that status could fire
 * AFTER a newer message re-badged the slot in other windows and wipe a badge
 * nobody read; flushing at the boundary sends "read up to the moment I left"
 * and can never cover anything that arrives after it. */
export function flushSlotRead(slot?: string): void {
  for (const [key, e] of [...pending]) {
    if (slot !== undefined && key !== slot) continue
    clearTimeout(e.timer)
    pending.delete(key)
    if (e.again) sendSlotReadImpl(key)
  }
}

/** Test hook: clear throttle state so cases don't leak windows into each other. */
export function _resetSlotReadRelayForTest(): void {
  for (const e of pending.values()) clearTimeout(e.timer)
  pending.clear()
  sendSlotReadImpl = () => {}
}
