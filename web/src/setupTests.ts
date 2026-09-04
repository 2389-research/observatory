// ABOUTME: Vitest setup: installs jest-dom matchers for every test file.
// ABOUTME: Referenced from vite.config.ts test.setupFiles.
import '@testing-library/jest-dom/vitest'

// jsdom implements neither of these, and xterm.js asks for both the moment it
// opens: matchMedia to follow the device pixel ratio, a 2d context to measure a
// character cell. jsdom's own getContext logs "Not implemented" and returns
// nothing, so it is replaced rather than left to shout through every run.
window.matchMedia ??= ((query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addListener() {},
  removeListener() {},
  addEventListener() {},
  removeEventListener() {},
  dispatchEvent: () => false,
})) as unknown as typeof window.matchMedia

HTMLCanvasElement.prototype.getContext = (() =>
  null) as unknown as HTMLCanvasElement['getContext']
