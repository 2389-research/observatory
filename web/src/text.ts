// ABOUTME: Renders untrusted guest-supplied strings inert for display.
// ABOUTME: SPEC §13.3 — a hostile name stays data, never markup or an invisible action.

/**
 * Code point ranges that reorder, hide, or fake the text around them. React
 * escapes markup already; these survive escaping and still mislead the eye.
 *
 * They are listed as numbers rather than string escapes on purpose: a literal
 * in the source would be invisible to the next reader of this file.
 */
const DANGEROUS: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f], // C0 controls, including ESC (terminal escape sequences)
  [0x007f, 0x009f], // DEL and C1 controls
  [0x061c, 0x061c], // Arabic letter mark
  [0x200b, 0x200f], // zero-width space/joiners, LRM, RLM
  [0x202a, 0x202e], // bidi embeddings and overrides
  [0x2066, 0x2069], // bidi isolates
  [0xfeff, 0xfeff], // zero-width no-break space (BOM)
]

function isDangerous(cp: number): boolean {
  return DANGEROUS.some(([lo, hi]) => cp >= lo && cp <= hi)
}

/** Replace every deceptive character with a visible <U+XXXX> marker. */
export function neutralize(s: string): string {
  let out = ''
  for (const ch of s) {
    const cp = ch.codePointAt(0)
    if (cp !== undefined && isDangerous(cp)) {
      out += `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`
    } else {
      out += ch
    }
  }
  return out
}

/** Coarse age for a fleet table: seconds, minutes, hours, then days. */
export function age(iso: string, now: number = Date.now()): string {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return 'unknown'
  const secs = Math.max(0, Math.floor((now - t) / 1000))
  if (secs < 60) return `${secs}s`
  if (secs < 3600) return `${Math.floor(secs / 60)}m`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`
  return `${Math.floor(secs / 86400)}d`
}
