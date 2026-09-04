// ABOUTME: The field set POST /vms and each POST /vm-batches member accept, in one component.
// ABOUTME: Single launch and batch launch render this; neither owns a private copy of the editor.
import { useMemo } from 'react'
import type { Template, VMDefaults, VMResources } from '../types'

/** What one VM request looks like while it is still being typed. */
export interface MemberDraft {
  name: string
  templateId: string
  vcpu: string
  memory: string
  rootDisk: string
  workspaceDisk: string
  labelsText: string
}

/** A blank field means "let the host decide", which the daemon reads as zero. */
export function num(text: string): number {
  const n = Number(text)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0
}

/**
 * Parse `key=value, key=value` into the labels map.
 *
 * Segments without an `=` produce no pair. The parsed result is rendered back
 * under the field so a dropped segment is visible rather than silent.
 */
export function parseLabels(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of text.split(',')) {
    const trimmed = part.trim()
    const eq = trimmed.indexOf('=')
    if (eq <= 0) continue
    const key = trimmed.slice(0, eq).trim()
    if (key !== '') out[key] = trimmed.slice(eq + 1).trim()
  }
  return out
}

/** A draft prefilled from the host's published defaults, never from constants here. */
export function blankMember(def: VMDefaults, templateId: string, name = ''): MemberDraft {
  return {
    name,
    templateId,
    vcpu: String(def.vcpu_count),
    memory: String(def.memory_mib),
    rootDisk: String(def.root_disk_mib),
    workspaceDisk: String(def.workspace_disk_mib),
    labelsText: '',
  }
}

export function draftResources(d: MemberDraft): VMResources {
  return {
    vcpu_count: num(d.vcpu),
    memory_mib: num(d.memory),
    root_disk_mib: num(d.rootDisk),
    workspace_disk_mib: num(d.workspaceDisk),
  }
}

/** The JSON body fields a draft contributes to POST /vms or a batch member. */
export function draftBody(d: MemberDraft): Record<string, unknown> {
  return {
    name: d.name,
    template_id: d.templateId,
    ...draftResources(d),
    labels: parseLabels(d.labelsText),
  }
}

interface Props {
  /** Distinguishes this instance's element ids; a batch renders several. */
  idPrefix: string
  draft: MemberDraft
  templates: Template[]
  onChange: (next: MemberDraft) => void
}

export function MemberFields({ idPrefix, draft, templates, onChange }: Props) {
  const labels = useMemo(() => parseLabels(draft.labelsText), [draft.labelsText])
  const set = <K extends keyof MemberDraft>(key: K, value: MemberDraft[K]) => onChange({ ...draft, [key]: value })
  const id = (field: string) => `${idPrefix}-${field}`

  return (
    <div className="launch-fields" data-testid="member-fields">
      <p className="field">
        <label htmlFor={id('name')}>Name</label>
        <input
          id={id('name')}
          value={draft.name}
          onChange={(e) => set('name', e.target.value)}
          placeholder="worker-1"
          autoComplete="off"
        />
      </p>
      <p className="field">
        <label htmlFor={id('template')}>Template</label>
        <select id={id('template')} value={draft.templateId} onChange={(e) => set('templateId', e.target.value)}>
          {templates.map((t) => (
            <option key={t.template_id} value={t.template_id}>
              {t.template_id}
            </option>
          ))}
        </select>
      </p>
      <p className="field">
        <label htmlFor={id('vcpu')}>vCPU count</label>
        <input id={id('vcpu')} type="number" min="1" value={draft.vcpu} onChange={(e) => set('vcpu', e.target.value)} />
      </p>
      <p className="field">
        <label htmlFor={id('memory')}>Memory (MiB)</label>
        <input
          id={id('memory')}
          type="number"
          min="1"
          value={draft.memory}
          onChange={(e) => set('memory', e.target.value)}
        />
      </p>
      <p className="field">
        <label htmlFor={id('root')}>Root disk (MiB)</label>
        <input
          id={id('root')}
          type="number"
          min="1"
          value={draft.rootDisk}
          onChange={(e) => set('rootDisk', e.target.value)}
        />
      </p>
      <p className="field">
        <label htmlFor={id('workspace')}>Workspace disk (MiB)</label>
        <input
          id={id('workspace')}
          type="number"
          min="0"
          value={draft.workspaceDisk}
          onChange={(e) => set('workspaceDisk', e.target.value)}
        />
      </p>
      <p className="field field-wide">
        <label htmlFor={id('labels')}>Labels</label>
        <input
          id={id('labels')}
          value={draft.labelsText}
          onChange={(e) => set('labelsText', e.target.value)}
          placeholder="team=infra, run=nightly"
          autoComplete="off"
        />
        <span className="hint" data-testid={`${idPrefix}-parsed-labels`}>
          {Object.keys(labels).length === 0
            ? 'key=value, comma separated'
            : Object.entries(labels)
                .map(([k, v]) => `${k}=${v}`)
                .join(' · ')}
        </span>
      </p>
    </div>
  )
}
