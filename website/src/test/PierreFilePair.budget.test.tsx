import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import type { FileContents } from '@pierre/diffs'
import { PIERRE_FILE_PAIR_MAX_LINES_PER_SIDE } from '../pierre/config'

const impl = vi.hoisted(() => ({ calls: 0 }))

vi.mock('../pierre/PierreImpl', () => ({
  PierreFilePairImpl: () => {
    impl.calls++
    return <div data-testid="pierre-file-pair" />
  },
}))

import { PierreFilePair } from '../pierre'

const file = (contents: string): FileContents => ({ name: 'generated.ts', contents })
const lines = (count: number) => Array.from({ length: count }, (_, i) => `const v${i} = ${i}`).join('\n')

beforeEach(() => {
  cleanup()
  impl.calls = 0
})

describe('PierreFilePair render budget', () => {
  it('keeps bounded pairs on the lazy Pierre implementation', async () => {
    render(<PierreFilePair oldFile={file('before')} newFile={file('after')} />)

    expect(await screen.findByTestId('pierre-file-pair')).toBeInTheDocument()
    expect(impl.calls).toBe(1)
  })

  it('keeps every oversized line without mounting Pierre, and marks the change', () => {
    const before = 'before sentinel\nunchanged'
    const after = `${lines(PIERRE_FILE_PAIR_MAX_LINES_PER_SIDE + 1)}
after sentinel`
    const { container } = render(
      <PierreFilePair oldFile={file(before)} newFile={file(after)} options={{ diffStyle: 'split' }} />,
    )

    expect(impl.calls).toBe(0)
    expect(container.querySelector('[data-pierre-plain-file-pair]')).toBeInTheDocument()
    expect(container.querySelector('[data-diffs-header]')).not.toBeInTheDocument()
    expect(screen.getByText('Large file — simplified view')).toBeInTheDocument()
    expect(container.querySelector('[data-pierre-plain-side="old"]')).toHaveAttribute('tabindex', '0')
    expect(container.querySelector('[data-pierre-plain-side="old"]')).toHaveAttribute('role', 'region')
    // Every source line is still present on each side; remove only the one
    // non-colour marker prefixed to the changed span.
    const sourceText = (pre: Element | null, marker: string) =>
      (pre?.textContent ?? '').replace(`${marker} `, '').replace(/\u200b/g, '')
    expect(sourceText(container.querySelector('[data-pierre-plain-side="old"]'), '−')).toBe(before)
    expect(sourceText(container.querySelector('[data-pierre-plain-side="new"]'), '+')).toBe(after)
    // The two files share no lines, so one constant-size span marks the whole
    // changed range instead of building one DOM node per line.
    const changed = container.querySelectorAll('[data-pierre-plain-side="new"] [data-changed]')
    expect(changed).toHaveLength(1)
    expect(changed[0].textContent).toContain('after sentinel')
    expect(screen.queryByTestId('pierre-file-pair')).not.toBeInTheDocument()
  })

  it('marks only the changed lines and does not strand the reader at line 1', () => {
    // A small edit deep in a large file (issue #9926): line ~870 of ~1000.
    const src = Array.from({ length: PIERRE_FILE_PAIR_MAX_LINES_PER_SIDE + 600 }, (_, i) => `const v${i} = ${i}`)
    const before = src.join('\n')
    const editAt = 869
    const afterArr = [...src]
    afterArr[editAt] = 'const v869 = 869 /* patched */'
    const { container } = render(
      <PierreFilePair oldFile={file(before)} newFile={file(afterArr.join('\n'))} options={{ diffStyle: 'split' }} />,
    )

    expect(impl.calls).toBe(0)
    const newSide = container.querySelector('[data-pierre-plain-side="new"]')
    const content = container.querySelector('[data-pierre-plain-content]')
    expect(content).toHaveClass('relative')
    const changed = newSide?.querySelector('[data-changed]')
    // One constant-size span marks the deep edit and records its 1-based anchor;
    // line 1 remains plain text outside it.
    expect(newSide?.querySelectorAll('[data-changed]')).toHaveLength(1)
    expect(changed).toHaveAttribute('data-first-changed-line', String(editAt + 1))
    expect(changed?.textContent).toContain('/* patched */')
    expect(changed?.textContent).not.toContain('const v0 = 0')
    expect(newSide?.textContent?.startsWith('const v0 = 0')).toBe(true)
  })

  it('renders every line plain when the two sides are identical', () => {
    const same = lines(PIERRE_FILE_PAIR_MAX_LINES_PER_SIDE + 1)
    const { container } = render(
      <PierreFilePair oldFile={file(same)} newFile={file(same)} options={{ diffStyle: 'split' }} />,
    )
    expect(impl.calls).toBe(0)
    // Identical content produces no span, so nothing is marked.
    expect(container.querySelectorAll('[data-changed]')).toHaveLength(0)
  })

  it('preserves a collapsed row header and every injected control', () => {
    const after = lines(PIERRE_FILE_PAIR_MAX_LINES_PER_SIDE + 1)
    const { container } = render(
      <PierreFilePair
        oldFile={file('before')}
        newFile={file(after)}
        options={{ collapsed: true, disableFileHeader: false }}
        fallbackContentStyle={{ maxHeight: 376, overflowY: 'auto' }}
        renderHeaderPrefix={() => <span data-testid="prefix" />}
        renderHeaderFilenameSuffix={() => <span data-testid="suffix" />}
        renderHeaderMetadata={() => <span data-testid="metadata" />}
      />,
    )

    expect(impl.calls).toBe(0)
    expect(container.querySelector('[data-diffs-header]')).toBeInTheDocument()
    expect(container.querySelector('[data-title]')).toHaveTextContent('generated.ts')
    expect(screen.getByTestId('prefix')).toBeInTheDocument()
    expect(screen.getByTestId('suffix')).toBeInTheDocument()
    expect(screen.getByTestId('metadata')).toBeInTheDocument()
    expect(screen.getByText('Large file — simplified view')).toBeInTheDocument()
    expect(container.querySelector('[data-pierre-plain-side]')).not.toBeInTheDocument()
  })

  it('keeps unified sides separated horizontally and applies caller-owned sizing', () => {
    const after = lines(PIERRE_FILE_PAIR_MAX_LINES_PER_SIDE + 1)
    const { container } = render(
      <PierreFilePair
        oldFile={file('before')}
        newFile={file(after)}
        options={{ diffStyle: 'unified' }}
        fallbackContentStyle={{ maxHeight: 376, overflowY: 'auto' }}
      />,
    )

    const content = container.querySelector('[data-pierre-plain-content]') as HTMLElement
    const sections = container.querySelectorAll('section')
    expect(content.style.maxHeight).toBe('376px')
    expect(content.style.overflowY).toBe('auto')
    expect(sections[1].className).toContain('border-t')
    expect(sections[1].className).not.toContain('md:border-l')
  })
})
