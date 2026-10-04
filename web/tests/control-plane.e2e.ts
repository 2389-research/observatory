// ABOUTME: Exercises real daemon HTTP, persisted annotations, and browser fleet controls.
// ABOUTME: Pins unavailable runtime outcomes without inventing guests or terminal output.
import { test } from '@e2e-dev/web'
import { expect } from 'e2e'

test('API discovery, bounded reads, unsupported capabilities and missing resources', async ({ app }) => {
  const get = (route: string) => fetch(`${app.baseUrl}/api/v1${route}`)
  const read = async (route: string) => {
    const response = await get(route)
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toContain('application/json')
    return response.json()
  }
  const meta = await read('/meta')
  expect(meta.service).toBe('vmobsd')
  expect(meta.api_version).toBe('v1')
  expect(meta.features.vms).toBe(true)
  expect(meta.features.execs).toBe(false)
  expect(meta.auth.required).toBe(false)
  expect(meta.links.templates).toBe('/api/v1/templates')
  expect(meta.limits.events_page_max).toBeGreaterThanOrEqual(meta.limits.events_page_default)

  const kinds = await read('/meta/event-kinds')
  const annotationKind = kinds.kinds.find((item: { kind: string }) => item.kind === 'annotation.created')
  expect(annotationKind.family).toBe('annotation')
  expect(annotationKind.provenance).toBe('host_observed')
  expect(annotationKind.schema_version).toBe(1)
  const templates = await read('/templates')
  expect(templates.templates).toHaveLength(1)
  expect(templates.templates[0].template_id).toBe('e2e-template')
  expect(templates.templates[0].digest).toMatch(/^sha256:[a-f0-9]{64}$/)
  expect(templates.templates[0].guest_privilege_profiles).toContain('unprivileged')

  const host = await read('/host/status')
  expect(host.runtime.available).toBe(false)
  expect(host.runtime.reason.length).toBeGreaterThan(0)
  expect(host.capacity.active_vms).toBe(0)
  expect(host.capacity.free_memory_mib + host.capacity.reserved_memory_mib).toBe(host.capacity.usable_memory_mib)
  expect(host.admission.max_batch_size).toBe(meta.limits.max_batch_size)
  expect(host.vm_defaults.memory_mib).toBeGreaterThan(0)
  expect(host.preflight.overall).toBe('fail')

  const situation = await read('/situation')
  expect(situation.host.vms_total).toBe(host.capacity.active_vms)
  expect(situation.host.vms_running).toBe(0)
  expect(situation.host.capacity_free_mib).toBe(host.capacity.free_memory_mib)
  expect(situation.host.watch.trigger_classes_active).toEqual(meta.attention_trigger_classes)
  expect(situation.attention_open).toBe(0)
  expect(situation.quiet).toBe(true)
  expect(situation.changed_vms).toEqual([])
  expect(situation.attention_head).toEqual([])
  expect(situation.omitted.attention_head.expand).toBe('/api/v1/attention')
  expect(situation.as_of_cursor).toMatch(/^\d+$/)

  for (const [route, field] of [
    ['/attention?limit=1', 'items'], ['/events?limit=1', 'events'],
    ['/runs?limit=1', 'runs'], ['/vms?limit=1', 'vms'],
    ['/annotations?limit=1', 'annotations'],
  ]) {
    const body = await read(route!)
    expect(body[field!]).toEqual([])
    expect(body.next_after).toBe('')
    if (field === 'events') expect(body.latest_event_id).toBe('')
  }
  const importer = await read('/telemetry/import')
  expect(importer.state).toBe('unknown')
  expect(importer.consecutive_failures).toBe('0')
  expect(importer.last_error).toBe('')
  expect(importer.last_success_at).toBe('')
  const identity = await read('/auth/session')
  expect(identity).toEqual({ owner: 'local_operator', method: 'none' })

  for (const route of ['/events?limit=invalid', '/annotations?after=invalid']) {
    const response = await get(route)
    expect(response.status).toBe(400)
    const error = await response.json()
    expect(error.code).toBe('malformed_request')
    expect(error.cause).toBe('query_parameter_invalid')
    expect(error.retryable).toBe(false)
  }
  const login = await fetch(`${app.baseUrl}/api/v1/auth/login`, { method: 'POST' })
  expect(login.status).toBe(409)
  expect((await login.json()).code).toBe('auth_disabled')
  const unsupported = await get('/events/stream')
  expect(unsupported.status).toBe(501)
  expect((await unsupported.json()).code).toBe('missing_capability')
  for (const route of ['/vms/absent', '/operations/op-999999', '/runs/run-999999', '/vm-batches/batch-999999']) {
    expect((await get(route)).status).toBe(404)
  }
  expect((await fetch(`${app.baseUrl}/api/v1/meta`, { method: 'POST' })).status).toBe(405)
})

test('annotation writes survive real SQLite reads and link to event history', async ({ app }) => {
  const text = `e2e-${crypto.randomUUID()}`
  const response = await fetch(`${app.baseUrl}/api/v1/annotations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_ref: 'host:main', text, tags: { suite: 'e2e' } }),
  })
  expect(response.status).toBe(201)
  const annotation = await response.json()
  expect(annotation.author).toBe('local_operator')
  expect(annotation.event_id.length).toBeGreaterThan(0)
  const list = await (await fetch(`${app.baseUrl}/api/v1/annotations?ref=host:main`)).json()
  expect(list.annotations.some((item: { text: string }) => item.text === text)).toBe(true)
  const events = await (await fetch(`${app.baseUrl}/api/v1/events?kind=annotation.created&tail=true&limit=100`)).json()
  expect(events.events.some((item: { event_id: string }) => item.event_id === annotation.event_id)).toBe(true)
  const invalid = await fetch(`${app.baseUrl}/api/v1/annotations`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  })
  expect(invalid.status).toBe(400)
})

test('fleet loads, filters persist, missing VM returns to the fleet', async ({ app, screen, browser }) => {
  await app.open('/ui/')
  await expect(screen.getByRole('heading', 'Firecracker Observatory')).toBeVisible()
  await expect(screen.getByRole('heading', 'VMs', { exact: true })).toBeVisible()
  await expect(screen.getByRole('button', 'Launch VM', { exact: true })).toBeEnabled()
  await screen.getByRole('checkbox', 'running', { exact: true }).check()
  await expect(browser).toHaveURL(/state=running/)
  await expect(screen.getByText('No VMs match this filter.', { exact: true })).toBeVisible()
  await browser.reload()
  await expect(screen.getByRole('checkbox', 'running', { exact: true })).toBeChecked()
  await app.open('/ui/?vm=absent')
  await expect(screen.getByRole('alert')).toContainText('vm_unknown')
  await screen.getByRole('button', '← Back to the fleet').tap()
  await expect(screen.getByRole('heading', 'VMs', { exact: true })).toBeVisible()
})

test('single and batch launch forms show the real unavailable-runtime refusal', async ({ app, screen, browser }) => {
  await app.open('/ui/')
  const single = screen.getByRole('form', 'Launch a VM', { exact: true })
  await expect(single.getByRole('button', 'Launch VM', { exact: true })).toBeEnabled()
  await single.getByRole('textbox', 'Name', { exact: true }).fill('e2e-single')
  await single.getByRole('button', 'Launch VM', { exact: true }).tap()
  await expect(single.getByRole('alert')).toContainText('runtime_unavailable')
  await browser.locator('summary').tap()
  const batch = screen.getByRole('form', 'Launch a batch', { exact: true })
  await expect(batch.getByRole('button', 'Launch batch', { exact: true })).toBeDisabled()
  await batch.getByRole('combobox', 'Reservation mode', { exact: true }).selectOption({ value: 'atomic_reservation' })
  await batch.getByRole('button', 'Add member').tap()
  await expect(batch.getByRole('button', 'Remove member 3')).toBeEnabled()
  await batch.getByRole('button', 'Remove member 3').tap()
  await expect(batch.getByRole('textbox', 'Name', { exact: true })).toHaveCount(2)
  await batch.getByRole('textbox', 'Name', { exact: true }).nth(0).fill('e2e-batch-1')
  await batch.getByRole('textbox', 'Name', { exact: true }).nth(1).fill('e2e-batch-2')
  await batch.getByRole('button', 'Launch batch', { exact: true }).tap()
  await expect(batch.getByRole('alert')).toContainText('runtime_unavailable')
  const vms = await (await fetch(`${app.baseUrl}/api/v1/vms`)).json()
  expect(vms.vms).toHaveLength(0)
})

test('annotation cursors traverse bounded pages without losing or repeating rows', async ({ app }) => {
  const expected: string[] = []
  for (let i = 0; i < 3; i++) {
    const text = `page-${crypto.randomUUID()}`
    expected.push(text)
    const response = await fetch(`${app.baseUrl}/api/v1/annotations`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_ref: 'host:main', text }),
    })
    expect(response.status).toBe(201)
  }
  const seen: string[] = []
  const ids: string[] = []
  let after = ''
  let exhausted = false
  for (let page = 0; page < 10; page++) {
    const response = await fetch(`${app.baseUrl}/api/v1/annotations?ref=host:main&limit=1&after=${after}`)
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.annotations.length).toBeLessThanOrEqual(1)
    if (body.annotations.length === 0) {
      exhausted = true
      break
    }
    ids.push(body.annotations[0].annotation_id)
    seen.push(body.annotations[0].text)
    expect(body.next_after).not.toBe(after)
    after = body.next_after
  }
  expect(exhausted).toBe(true)
  expect(new Set(ids).size).toBe(ids.length)
  for (const text of expected) expect(seen).toContain(text)
})
