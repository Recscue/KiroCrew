/**
 * Settings ▸ Chat — the feature-video cache readout and its one action.
 *
 * The row is a READOUT of backend state, so what these tests own is the mapping
 * from that state to what the user sees: which of the three lines is shown, and
 * whether the manual control exists at all. The counts themselves are the
 * backend's business.
 *
 * Two of these are mutation-verified below, in the tests that say so: the
 * download-disabled gate and the in-flight gate are the two places where the
 * wrong answer puts a button in front of the user that cannot do anything.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'

import { i18nT } from '../i18n/t'

const BASE_DASH = {
  restore_sessions: false,
  restore_window_minutes: 30,
  merge_queued_messages: false,
  widget_density: 'more' as const,
  verbosity: 'default' as const,
  quick_send: false,
  session_grid: false,
  tail_fork_enabled: false,
  link_previews: false,
}

/** Every clip of the current release already on disk, downloads permitted. */
const BASE_STATUS = {
  enabled: true,
  download_enabled: true,
  release: '2026.09.1',
  cached: 2,
  total: 3,
  downloading: null as string | null,
  state: 'idle',
}

const { featureVideoStatusMock, featureVideoFetchAllMock } = vi.hoisted(() => ({
  featureVideoStatusMock: vi.fn(),
  featureVideoFetchAllMock: vi.fn(),
}))

vi.mock('../api/client', () => ({
  api: {
    dashboardConfig: () => Promise.resolve({ ...BASE_DASH }),
    voiceConfig: () => Promise.resolve({ enabled: false, voice: 'Ruth', engine: 'neural', rate: '100%', autoSpeak: false, aws_profile: '', region: '' }),
    sttConfig: () => Promise.resolve({ enabled: false, provider: '', model: '', available: false, streaming: false, transcribe_region: '', transcribe_profile: '', language_code: 'en-US', models: {}, language_codes: [] }),
    kirocrewConfig: () => Promise.resolve({ agent: { completion_keep: 'head', completion_keep_chars: 3000, model: 'auto', reasoning_effort: '' } }),
    models: () => Promise.resolve([{ model_name: 'auto', description: 'Default' }]),
    patchConfig: () => Promise.resolve({}),
    updateDashboardConfig: () => Promise.resolve({}),
    updateVoiceConfig: () => Promise.resolve({}),
    updateSttConfig: () => Promise.resolve({}),
    tipsStatus: () => Promise.resolve({ enabled_config: true, opted_out: false }),
    tipsFeedback: () => Promise.resolve({ ok: true }),
    featureVideoStatus: featureVideoStatusMock,
    featureVideoFetchAll: featureVideoFetchAllMock,
  },
}))

import { ChatPanel } from '../pages/settings/ChatPanel'

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

const statusLine = () => screen.queryByTestId('feature-video-status')
const downloadBtn = () =>
  screen.queryByRole('button', { name: i18nT('pages.settings.chatPanel.feature_videos_download_all') })

beforeEach(() => {
  featureVideoStatusMock.mockReset()
  featureVideoStatusMock.mockResolvedValue({ ...BASE_STATUS })
  featureVideoFetchAllMock.mockReset()
  featureVideoFetchAllMock.mockResolvedValue({ ok: true })
})

describe('ChatPanel — the feature-video cache readout', () => {
  it('names the release it is counting, and how much of it is on disk', async () => {
    // The release matters as much as the counts: 2 of 3 for LAST release is a stale
    // cache, and the same two numbers with this release is a cache mid-fill.
    wrap(<ChatPanel />)
    await waitFor(() => expect(statusLine()).toBeInTheDocument())
    expect(statusLine()).toHaveTextContent('2026.09.1')
    expect(statusLine()).toHaveTextContent('2')
    expect(statusLine()).toHaveTextContent('3')
  })

  it('names the clip being fetched while one is in flight', async () => {
    featureVideoStatusMock.mockResolvedValue({ ...BASE_STATUS, downloading: 'monitor-loops', state: 'downloading' })
    wrap(<ChatPanel />)
    await waitFor(() => expect(statusLine()).toHaveTextContent('monitor-loops'))
  })

  it('the live state outranks the counts', async () => {
    // Both are true at once while a fetch runs. The counts are a fact the user can
    // read a second later; "something is happening right now" is the one that
    // explains why the button is unavailable.
    featureVideoStatusMock.mockResolvedValue({ ...BASE_STATUS, downloading: 'feature-tips' })
    wrap(<ChatPanel />)
    await waitFor(() => expect(statusLine()).toBeInTheDocument())
    expect(statusLine()).toHaveTextContent(
      i18nT('pages.settings.chatPanel.feature_videos_downloading', { id: 'feature-tips' }),
    )
  })

  it('says so when policy forbids downloads', async () => {
    featureVideoStatusMock.mockResolvedValue({ ...BASE_STATUS, download_enabled: false })
    wrap(<ChatPanel />)
    await waitFor(() => expect(statusLine()).toHaveTextContent(
      i18nT('pages.settings.chatPanel.feature_videos_downloads_disabled'),
    ))
  })

  it('shows no row at all when the feature is off', async () => {
    // A cache count for clips that never play is noise, and an operator who turned
    // the feature off is not asking about its disk usage.
    featureVideoStatusMock.mockResolvedValue({ ...BASE_STATUS, enabled: false })
    wrap(<ChatPanel />)
    await waitFor(() => expect(screen.getByText(i18nT('pages.settings.chatPanel.feature_tips'))).toBeInTheDocument())
    expect(statusLine()).not.toBeInTheDocument()
    expect(downloadBtn()).not.toBeInTheDocument()
  })

  it('says which half broke when the read fails', async () => {
    // A row that simply vanishes is indistinguishable from the feature being off.
    featureVideoStatusMock.mockRejectedValue(new Error('HTTP 500'))
    wrap(<ChatPanel />)
    await waitFor(() => expect(screen.getByText(
      i18nT('pages.settings.chatPanel.failed_to_load_feature_video_status'),
    )).toBeInTheDocument())
  })
})

describe('ChatPanel — downloading every clip now', () => {
  it('offers the control once downloads are permitted, and starts the fetch', async () => {
    wrap(<ChatPanel />)
    await waitFor(() => expect(downloadBtn()).toBeInTheDocument())
    fireEvent.click(downloadBtn() as HTMLElement)
    await waitFor(() => expect(featureVideoFetchAllMock).toHaveBeenCalledTimes(1))
  })

  it('hides the control entirely when policy forbids downloads', async () => {
    // MUTATION-VERIFIED: rendering the button `disabled` instead of absent, or
    // dropping the `download_enabled` condition, both fail here. Hidden and not
    // greyed, because a control whose only outcome is a refusal explains a policy
    // the user cannot act on.
    featureVideoStatusMock.mockResolvedValue({ ...BASE_STATUS, download_enabled: false })
    wrap(<ChatPanel />)
    await waitFor(() => expect(statusLine()).toBeInTheDocument())
    expect(downloadBtn()).not.toBeInTheDocument()
    // Not a greyed one either, in any spelling.
    const disabled = screen.queryAllByRole('button').filter(b => b.hasAttribute('disabled'))
    expect(disabled).toHaveLength(0)
    expect(featureVideoFetchAllMock).not.toHaveBeenCalled()
  })

  it('cannot queue the same work twice while a fetch is already running', async () => {
    // MUTATION-VERIFIED: dropping the `!!fv.downloading` clause lets this click
    // through and starts a second pass over the same clips.
    featureVideoStatusMock.mockResolvedValue({ ...BASE_STATUS, downloading: 'feature-tips' })
    wrap(<ChatPanel />)
    await waitFor(() => expect(downloadBtn()).toBeInTheDocument())
    expect(downloadBtn()).toBeDisabled()
    fireEvent.click(downloadBtn() as HTMLElement)
    expect(featureVideoFetchAllMock).not.toHaveBeenCalled()
  })

  it('says so when the fetch could not be started', async () => {
    featureVideoFetchAllMock.mockRejectedValue(new Error('HTTP 503'))
    wrap(<ChatPanel />)
    await waitFor(() => expect(downloadBtn()).toBeInTheDocument())
    fireEvent.click(downloadBtn() as HTMLElement)
    await waitFor(() => expect(screen.getByText(
      i18nT('pages.settings.chatPanel.failed_to_start_feature_video_download'),
    )).toBeInTheDocument())
  })
})
