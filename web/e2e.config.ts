// ABOUTME: Starts the real Go daemon for isolated browser and HTTP acceptance checks.
// ABOUTME: Uses no AI provider, runtime mock, installed state, or production endpoint.
import type { E2EConfig } from 'e2e'
import { web } from '@e2e-dev/web'

export default {
  tests: 'tests/**/*.e2e.ts',
  workers: 1,
  retries: 0,
  targets: [{
    name: 'local-chromium',
    engine: web(),
    app: {
      url: 'http://127.0.0.1:0',
      readyUrl: 'http://127.0.0.1:{port}/api/v1/meta',
      command: {
        executable: 'sh',
        args: ['../scripts/e2e-server', '{port}'],
        startupTimeout: 120_000,
        log: '.e2e/logs/daemon.log',
      },
    },
  }],
} satisfies E2EConfig
