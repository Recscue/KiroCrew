/**
 * Cross-window unread-badge sync: the `slot_read` relay.
 *
 * Read marks were window-local (Redux + localStorage), so reading a session
 * in one dashboard window left the sidebar bubble lit in every other one.
 * These specs pin the three legs of the fix:
 *
 *  - the relay module's per-slot throttle (leading send, one coalesced
 *    trailing send, never a dropped final read),
 *  - the socket wiring: an inbound `slot_read` frame clears the local badge
 *    and never echoes back out; the arrival branch relays a read only for
 *    this window's visible active slot,
 *  - the read-gesture sites: `switchSlot` relays the slot it just read.
 *
 * Harness mirrors UseWebSocketCoverage: the hook dispatches through the
 * Provider store but reads `activeSlot` off the singleton store, so tests
 * prime both and reset both.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { createElement } from 'react'
import { Provider } from 'react-redux'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createTestStore } from './helpers'
import { useWebSocket } from '../hooks/useWebSocket'
import { store as globalStore } from '../store'
import chatReducer, { setActiveSlot, clearMessages, switchSlot } from '../store/chatSlice'
import dashboardReducer, { markSlotRead, markSlotUnread } from '../store/dashboardSlice'
import { bindSlotReadSender, emitSlotRead, flushSlotRead, _resetSlotReadRelayForTest } from '../lib/slotReadRelay'

/** Flip jsdom's document.hidden and fire the visibilitychange the hook listens for. */
const setDocumentHidden = (v: boolean) => {
  Object.defineProperty(document, 'hidden', { value: v, configurable: true })
  document.dispatchEvent(new Event('visibilitychange'))
}

vi.mock('../api/client', () => ({
  api: {
    chatSlots: vi.fn().mockResolvedValue([]),
    voiceConfig: vi.fn().mockResolvedValue({ autoSpeak: false }),
    approvals: vi.fn().mockResolvedValue([]),
    notifications: vi.fn().mockResolvedValue({ notifications: [], unread: 0 }),
    chatSlotDetail: vi.fn().mockResolvedValue({ messages: [], running: false, has_more: false, total: 0, queue: [] }),
    autonudgeList: vi.fn().mockResolvedValue({ enabled: false, loops: [] }),
    monitorsList: vi.fn().mockResolvedValue({ enabled: false, monitors: [] }),
    pendingQuestions: vi.fn().mockResolvedValue([]),
    sessions: vi.fn().mockResolvedValue({ sessions: [], has_more: false }),
  },
}))

const ACTIVE = 'slot-active'
const BACKGROUND = 'slot-background'

const WS_INSTANCES: MockWebSocket[] = []

class MockWebSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3
  readyState = MockWebSocket.CONNECTING
  onopen: ((ev: Event) => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  onclose: ((ev: CloseEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null
  send = vi.fn()
  close = vi.fn(() => { this.readyState = MockWebSocket.CLOSED })
  constructor(public url: string) { WS_INSTANCES.push(this) }
  simulateOpen() { this.readyState = MockWebSocket.OPEN; this.onopen?.(new Event('open')) }
  simulateMessage(data: unknown) { this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(data) })) }
}

describe('slotReadRelay module throttle', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    _resetSlotReadRelayForTest()
  })
  afterEach(() => {
    _resetSlotReadRelayForTest()
    vi.useRealTimers()
  })

  it('sends the first read immediately (leading edge)', () => {
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('k1')
    expect(sent).toEqual(['k1'])
  })

  it('coalesces a burst into exactly one trailing send', () => {
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('k1')
    emitSlotRead('k1')
    emitSlotRead('k1')
    expect(sent).toEqual(['k1'])          // burst suppressed…
    vi.advanceTimersByTime(1_000)
    expect(sent).toEqual(['k1', 'k1'])    // …but the LAST read still lands
    vi.advanceTimersByTime(5_000)
    expect(sent).toEqual(['k1', 'k1'])    // trailing send does not self-perpetuate
  })

  it('a quiet window with no repeat sends nothing at its end', () => {
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('k1')
    vi.advanceTimersByTime(5_000)
    expect(sent).toEqual(['k1'])
  })

  it('throttles per slot, not globally', () => {
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('k1')
    emitSlotRead('k2')
    expect(sent).toEqual(['k1', 'k2'])
  })

  it('is a safe no-op unbound and for an empty key', () => {
    expect(() => emitSlotRead('k1')).not.toThrow()
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('')
    expect(sent).toEqual([])
  })

  it('flush sends a pending trailing relay immediately and disarms its timer', () => {
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('k1')
    emitSlotRead('k1')          // leading sent + trailing pending
    flushSlotRead('k1')
    expect(sent).toEqual(['k1', 'k1'])
    vi.advanceTimersByTime(5_000)
    expect(sent).toEqual(['k1', 'k1'])  // timer disarmed: no third send
  })

  it('flush of a quiet window sends nothing extra', () => {
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('k1')          // leading only, no repeat
    flushSlotRead('k1')
    vi.advanceTimersByTime(5_000)
    expect(sent).toEqual(['k1'])
  })

  it('a targeted flush leaves other slots pending', () => {
    const sent: string[] = []
    bindSlotReadSender(s => sent.push(s))
    emitSlotRead('k1'); emitSlotRead('k1')
    emitSlotRead('k2'); emitSlotRead('k2')
    flushSlotRead('k1')
    expect(sent).toEqual(['k1', 'k2', 'k1'])
    vi.advanceTimersByTime(1_000)
    expect(sent).toEqual(['k1', 'k2', 'k1', 'k2'])  // k2 trailing untouched
  })
})

describe('slot_read over the dashboard socket', () => {
  let testStore: ReturnType<typeof createTestStore>

  beforeEach(() => {
    vi.clearAllMocks()
    _resetSlotReadRelayForTest()
    WS_INSTANCES.length = 0
    testStore = createTestStore({
      chat: { ...chatReducer(undefined, { type: '@@INIT' }), activeSlot: ACTIVE },
    })
    vi.stubGlobal('WebSocket', MockWebSocket)
    globalStore.dispatch(setActiveSlot(ACTIVE))
  })

  afterEach(() => {
    _resetSlotReadRelayForTest()
    setDocumentHidden(false)
    vi.unstubAllGlobals()
    globalStore.dispatch(clearMessages())
    globalStore.dispatch(setActiveSlot(null))
  })

  function wrapper({ children }: { children: React.ReactNode }) {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    return createElement(Provider, { store: testStore },
      createElement(QueryClientProvider, { client: qc }, children))
  }

  function mount() {
    const hook = renderHook(() => useWebSocket(), { wrapper })
    const ws = WS_INSTANCES[0]
    act(() => { ws.simulateOpen() })
    return { ...hook, ws }
  }

  const dash = () => testStore.getState().dashboard
  const sentReadFrames = (ws: MockWebSocket) =>
    ws.send.mock.calls.map(c => c[0] as string).filter(f => f.includes('"slot_read"'))

  it('an inbound slot_read frame retires the local unread badge', () => {
    const { ws } = mount()
    testStore.dispatch(markSlotUnread(BACKGROUND))
    expect(dash().unreadSlots).toContain(BACKGROUND)
    act(() => { ws.simulateMessage({ type: 'slot_read', data: { slot: BACKGROUND } }) })
    expect(dash().unreadSlots).not.toContain(BACKGROUND)
  })

  it('an inbound slot_read never echoes back out (no relay loop)', () => {
    const { ws } = mount()
    testStore.dispatch(markSlotUnread(BACKGROUND))
    act(() => { ws.simulateMessage({ type: 'slot_read', data: { slot: BACKGROUND } }) })
    expect(sentReadFrames(ws)).toEqual([])
  })

  it('a malformed slot_read frame is ignored', () => {
    const { ws } = mount()
    testStore.dispatch(markSlotUnread(BACKGROUND))
    act(() => { ws.simulateMessage({ type: 'slot_read', data: {} }) })
    act(() => { ws.simulateMessage({ type: 'slot_read', data: { slot: 42 } }) })
    expect(dash().unreadSlots).toContain(BACKGROUND)
  })

  it('a message landing in the visible active slot relays a read', () => {
    const { ws } = mount()
    act(() => {
      ws.simulateMessage({ type: 'chat_message', data: { slot: ACTIVE, role: 'assistant', content: 'hi', ts: '2026-09-10T00:00:00Z' } })
    })
    expect(sentReadFrames(ws)).toEqual([JSON.stringify({ type: 'slot_read', slot: ACTIVE })])
  })

  it('a message landing in a background slot badges it and relays nothing', () => {
    const { ws } = mount()
    act(() => {
      ws.simulateMessage({ type: 'chat_message', data: { slot: BACKGROUND, role: 'assistant', content: 'hi', ts: '2026-09-10T00:00:00Z' } })
    })
    expect(dash().unreadSlots).toContain(BACKGROUND)
    expect(sentReadFrames(ws)).toEqual([])
  })

  it('switchSlot relays the read of the slot it opens', async () => {
    const { ws } = mount()
    await act(async () => { await testStore.dispatch(switchSlot(BACKGROUND) as never) })
    expect(sentReadFrames(ws)).toContain(JSON.stringify({ type: 'slot_read', slot: BACKGROUND }))
  })

  it('switching away flushes the outgoing slot\'s pending trailing relay', () => {
    const { ws } = mount()
    act(() => {
      // Two arrivals in the visible active slot: leading frame + pending trailing.
      ws.simulateMessage({ type: 'chat_message', data: { slot: ACTIVE, role: 'assistant', content: 'a', ts: '2026-09-10T00:00:00Z' } })
      ws.simulateMessage({ type: 'chat_message', data: { slot: ACTIVE, role: 'assistant', content: 'b', ts: '2026-09-10T00:00:01Z' } })
    })
    expect(sentReadFrames(ws)).toEqual([JSON.stringify({ type: 'slot_read', slot: ACTIVE })])
    // The slot stops being visible-active: the coalesced trailing read goes
    // out NOW, so no timer survives to wipe a later re-badge.
    act(() => { globalStore.dispatch(setActiveSlot(BACKGROUND)) })
    expect(sentReadFrames(ws)).toEqual([
      JSON.stringify({ type: 'slot_read', slot: ACTIVE }),
      JSON.stringify({ type: 'slot_read', slot: ACTIVE }),
    ])
  })

  it('a hidden-tab arrival parks, and revealing the tab relays the read', () => {
    const { ws } = mount()
    act(() => { setDocumentHidden(true) })
    act(() => {
      ws.simulateMessage({ type: 'chat_message', data: { slot: ACTIVE, role: 'assistant', content: 'hi', ts: '2026-09-10T00:00:00Z' } })
    })
    expect(sentReadFrames(ws)).toEqual([])         // hidden window isn't reading
    act(() => { setDocumentHidden(false) })        // …returning to it IS
    expect(sentReadFrames(ws)).toEqual([JSON.stringify({ type: 'slot_read', slot: ACTIVE })])
  })

  it('a parked hidden arrival for a slot no longer active relays nothing', () => {
    const { ws } = mount()
    act(() => { setDocumentHidden(true) })
    act(() => {
      ws.simulateMessage({ type: 'chat_message', data: { slot: ACTIVE, role: 'assistant', content: 'hi', ts: '2026-09-10T00:00:00Z' } })
    })
    act(() => { globalStore.dispatch(setActiveSlot(BACKGROUND)) })
    act(() => { setDocumentHidden(false) })
    expect(sentReadFrames(ws)).toEqual([])
  })

  it('markSlotRead is a persistence no-op for a key that is not unread', () => {
    const spy = vi.spyOn(Storage.prototype, 'setItem')
    const before = dashboardReducer(undefined, { type: '@@INIT' })
    spy.mockClear()
    const after = dashboardReducer(before, markSlotRead('never-unread'))
    expect(after.unreadSlots).toEqual(before.unreadSlots)
    expect(spy).not.toHaveBeenCalled()             // echo fan-in writes nothing
    spy.mockRestore()
  })
})
