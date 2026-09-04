// ABOUTME: SPEC §13.7's contrast rule, checked against the stylesheet itself.
// ABOUTME: jsdom applies no cascade, so a computed-style assertion here would be fiction.
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// Built from this file's own path rather than `new URL('./styles.css',
// import.meta.url)`, which Vite rewrites into an asset reference.
const css = readFileSync(fileURLToPath(import.meta.url).replace(/styles\.test\.ts$/, 'styles.css'), 'utf8')

type RGB = [number, number, number]

function parseColor(raw: string, tokens: Map<string, string>): RGB | null {
  let v = raw.trim().replace(/;$/, '')
  const varName = /^var\((--[a-z-]+)\)$/.exec(v)?.[1]
  if (varName) {
    const resolved = tokens.get(varName)
    if (resolved === undefined) return null
    v = resolved
  }
  const hex = /^#([0-9a-f]{6})$/i.exec(v)?.[1]
  if (hex) {
    const n = parseInt(hex, 16)
    return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
  }
  const rgba = /^rgba?\(\s*(\d+)[ ,]+(\d+)[ ,]+(\d+)(?:[ ,/]+([\d.]+))?\s*\)$/i.exec(v)
  if (rgba) {
    const base: RGB = [Number(rgba[1]), Number(rgba[2]), Number(rgba[3])]
    const alpha = rgba[4] === undefined ? 1 : Number(rgba[4])
    // Translucent fills sit on the panel; composite so the check sees the
    // colour a reader actually sees.
    const panel = parseColor('var(--panel)', tokens) ?? [0, 0, 0]
    return base.map((c, i) => Math.round(c * alpha + (panel[i] ?? 0) * (1 - alpha))) as RGB
  }
  return null // inherit, transparent, none, currentColor, gradients
}

function luminance([r, g, b]: RGB): number {
  const channel = (c: number) => {
    const s = c / 255
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

function contrast(fg: RGB, bg: RGB): number {
  const a = luminance(fg)
  const b = luminance(bg)
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
}

// The capture groups below are mandatory in their patterns; the `= ''` defaults
// exist only because a matchAll group is typed as possibly-undefined.
const tokens = new Map<string, string>()
for (const [, name = '', value = ''] of css.matchAll(/(--[a-z-]+):\s*([^;]+);/g)) {
  tokens.set(name, value.trim())
}

interface Rule {
  selector: string
  color: string | null
  background: string | null
}

const rules: Rule[] = []
for (const [, selector = '', body = ''] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
  const color = [...body.matchAll(/(?:^|[;\s])color:\s*([^;]+)/g)].pop()?.[1] ?? null
  const background = [...body.matchAll(/(?:^|[;\s])background(?:-color)?:\s*([^;]+)/g)].pop()?.[1] ?? null
  rules.push({ selector: selector.trim().replace(/\s+/g, ' '), color, background })
}

// Every surface the page paints text on. A rule that names its own background
// is checked against that one; a rule that inherits its background could be
// anywhere, so it must clear all of them.
const SURFACES = ['var(--bg)', 'var(--panel)', '#21262d', 'rgba(248, 81, 73, 0.1)']

describe('styles.css contrast (SPEC §13.7: 4.5:1 for text)', () => {
  it('found the token block and the rules to check', () => {
    expect(tokens.get('--ink')).toBe('#e6edf3')
    expect(rules.filter((r) => r.color !== null).length).toBeGreaterThan(20)
  })

  it('paints no text below 4.5:1 on any surface it can land on', () => {
    const failures: string[] = []
    for (const rule of rules) {
      if (rule.color === null) continue
      const fg = parseColor(rule.color, tokens)
      if (fg === null) continue
      const own = rule.background === null ? null : parseColor(rule.background, tokens)
      const backgrounds = own === null ? SURFACES.map((s) => parseColor(s, tokens)!) : [own]
      for (const bg of backgrounds) {
        const ratio = contrast(fg, bg)
        if (ratio < 4.5) {
          failures.push(
            `${rule.selector} { color: ${rule.color.trim()} } on rgb(${bg.join(',')}) = ${ratio.toFixed(2)}:1`,
          )
        }
      }
    }
    expect(failures).toEqual([])
  })
})

describe('styles.css keyboard affordances (SPEC §13.7)', () => {
  it('gives focus a visible ring rather than removing the outline', () => {
    expect(css).toMatch(/:focus-visible/)
    expect(css).not.toMatch(/outline:\s*(none|0)\s*;(?![^}]*:focus-visible)/)
  })
})
