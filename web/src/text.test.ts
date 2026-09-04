// ABOUTME: SPEC 13.3's sanitizer, checked against real hostile strings.
// ABOUTME: React escapes markup; these characters survive escaping and still lie to the eye.
import { describe, it, expect } from 'vitest'
import { neutralize, age } from './text'

// Built from code points, never typed as literals: the whole point of these
// characters is that a reader of the source cannot see them.
const cp = (n: number) => String.fromCodePoint(n)
const RLO = cp(0x202e) // right-to-left override
const ESC = cp(0x1b) // the start of an ANSI sequence
const ZWSP = cp(0x200b)
const BOM = cp(0xfeff)

/**
 * The ranges neutralize claims to clear, restated here so this test is its own
 * spec rather than a mirror of the implementation's table.
 */
const DECEPTIVE: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x061c, 0x061c],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
]

function hasDeceptive(s: string): boolean {
  for (const ch of s) {
    const n = ch.codePointAt(0) ?? 0
    if (DECEPTIVE.some(([lo, hi]) => n >= lo && n <= hi)) return true
  }
  return false
}

const marker = (n: number) => `<U+${n.toString(16).toUpperCase().padStart(4, '0')}>`

describe('neutralize (SPEC 13.3)', () => {
  it('defuses the right-to-left override that disguises an executable', () => {
    // The classic: reads to the eye as an image, runs as an executable.
    const out = neutralize(`invoice${RLO}gnp.exe`)
    expect(out).toBe('invoice<U+202E>gnp.exe')
    expect(hasDeceptive(out)).toBe(false)
  })

  it('defuses an ANSI escape sequence, so a name cannot repaint the page', () => {
    expect(neutralize(`${ESC}[31mDANGER${ESC}[0m`)).toBe('<U+001B>[31mDANGER<U+001B>[0m')
  })

  it('makes zero-width characters visible, so two names cannot look identical', () => {
    expect(neutralize(`agent${ZWSP}-03`)).toBe('agent<U+200B>-03')
    expect(neutralize(`${BOM}agent`)).toBe('<U+FEFF>agent')
    expect(neutralize(`agent${ZWSP}-03`)).not.toBe(neutralize('agent-03'))
  })

  it('defuses bidi isolates and the Arabic letter mark', () => {
    expect(neutralize(`${cp(0x2066)}a${cp(0x2069)}`)).toBe('<U+2066>a<U+2069>')
    expect(neutralize(`${cp(0x61c)}x`)).toBe('<U+061C>x')
  })

  it('defuses the C1 controls, not only the C0 ones', () => {
    expect(neutralize(`${cp(0x7f)}${cp(0x85)}`)).toBe('<U+007F><U+0085>')
  })

  it('leaves every string an operator actually types alone', () => {
    for (const safe of ['agent-03', 'caf\u00e9', 'ok', 'a<b>&c', 'name with spaces', '']) {
      expect(neutralize(safe)).toBe(safe)
    }
  })

  it('leaves no deceptive character in the output, whatever went in', () => {
    // One of every boundary the ranges name, wrapped in ordinary text.
    const points = [0x00, 0x1f, 0x7f, 0x9f, 0x61c, 0x200b, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069, 0xfeff]
    const out = neutralize('vm-' + points.map(cp).join('x') + '-end')
    expect(hasDeceptive(out)).toBe(false)
    expect(out).toContain('vm-')
    expect(out).toContain('-end')
    for (const n of points) expect(out).toContain(marker(n))
  })

  it('does not split an astral character while walking the string', () => {
    // Iterating UTF-16 units instead of code points would cut this in half.
    const rocket = cp(0x1f680)
    expect(neutralize(`a${rocket}b`)).toBe(`a${rocket}b`)
  })
})

describe('age', () => {
  const now = Date.parse('2026-09-04T12:00:00Z')

  it('reads seconds, minutes, hours and days', () => {
    expect(age('2026-09-04T11:59:30Z', now)).toBe('30s')
    expect(age('2026-09-04T11:30:00Z', now)).toBe('30m')
    expect(age('2026-09-04T06:00:00Z', now)).toBe('6h')
    expect(age('2026-09-01T12:00:00Z', now)).toBe('3d')
  })

  it('says unknown rather than inventing an age for an unparseable timestamp', () => {
    expect(age('not a timestamp', now)).toBe('unknown')
  })

  it('clamps a clock skew forward to zero instead of showing a negative age', () => {
    expect(age('2026-09-04T12:00:30Z', now)).toBe('0s')
  })
})
