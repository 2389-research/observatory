// ABOUTME: Checks unavailable capture and unknown loss stay distinct from a healthy channel.
// ABOUTME: Exercises real rendering with data fixtures, not deployed collector evidence.
import { render, screen, within } from '@testing-library/react'
import { expect, it } from 'vitest'
import { CoveragePanel } from './CoveragePanel'
import type { CaptureCoverage } from '../types'
const coverage: CaptureCoverage = {
  vm_id: 'vm-a',
  boot_id: 'boot-a',
  channel: { state: 'healthy', observed_dropped: '4' },
  collectors: [
    {
      id: 'filesystem',
      state: 'unavailable',
      enabled: true,
      event_classes: [],
      scope: [],
      exclusions: [],
      limitations: [],
      observed_dropped: null,
      unknown_loss_intervals: null,
      source: 'guest',
      provenance: 'guest_reported',
      reason: 'collector absent',
    },
    {
      id: 'flow',
      state: 'healthy',
      enabled: true,
      event_classes: ['net.flow'],
      scope: ['VM namespace'],
      exclusions: [],
      limitations: [],
      observed_dropped: '0',
      unknown_loss_intervals: 0,
      source: 'host',
      provenance: 'host_observed',
    },
  ],
  gaps: ['filesystem:unavailable'],
}
it('shows healthy transport separately from missing capture and unknown counters', () => {
  render(<CoveragePanel coverage={coverage} failure="" />)
  expect(screen.getByTestId('channel-coverage')).toHaveTextContent('Transport healthy')
  expect(screen.getByTestId('channel-coverage')).toHaveTextContent('4 observed drops')
  const fs = screen.getByTestId('coverage-filesystem')
  expect(fs).toHaveTextContent('unavailable')
  expect(fs).toHaveTextContent('unknown observed drops')
  expect(within(fs).queryByText('0 observed drops')).toBeNull()
  expect(screen.getByTestId('coverage-flow')).toHaveTextContent('0 observed drops')
})
it('labels retained coverage stale when refresh fails', () => {
  render(<CoveragePanel coverage={coverage} failure="connection lost" />)
  expect(screen.getByRole('alert')).toHaveTextContent(/last report.*stale/i)
})
