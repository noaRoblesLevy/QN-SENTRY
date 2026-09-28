import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { Finding, ModuleName } from '../types'
import { MODULE_LABELS, MODULES, severityRank } from '../lib/labels'
import { plural } from '../lib/format'
import SeverityBadge from './SeverityBadge'
import './FindingsTable.css'

/** Findings grouped per module and sorted by severity (issue #15) */
function FindingsTable({ findings }: { findings: Finding[] }) {
  const [openIds, setOpenIds] = useState<Set<number>>(new Set())

  function toggle(id: number) {
    setOpenIds((previous) => {
      const next = new Set(previous)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const groups = MODULES.map((module) => ({
    module,
    findings: findings
      .filter((f) => f.module === module)
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title)),
  })).filter((group) => group.findings.length > 0)

  return (
    <table className="data-table findings-table">
      <thead>
        <tr>
          <th scope="col" className="col-severity">
            Severity
          </th>
          <th scope="col">Finding</th>
        </tr>
      </thead>
      {groups.map((group) => (
        <tbody key={group.module}>
          <GroupHeader module={group.module} count={group.findings.length} />
          {group.findings.map((finding) => {
            const open = openIds.has(finding.id)
            const detailsId = `finding-${finding.id}-details`
            return (
              <Fragment key={finding.id}>
                <tr className="finding-row">
                  <td>
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td>
                    <button
                      type="button"
                      className="finding-toggle"
                      aria-expanded={open}
                      aria-controls={detailsId}
                      onClick={() => toggle(finding.id)}
                    >
                      {open ? (
                        <ChevronDown size={16} strokeWidth={1.5} aria-hidden="true" />
                      ) : (
                        <ChevronRight size={16} strokeWidth={1.5} aria-hidden="true" />
                      )}
                      <span className="finding-title">{finding.title}</span>
                    </button>
                    <div className="finding-asset mono muted">{finding.asset}</div>
                  </td>
                </tr>
                {open && (
                  <tr id={detailsId} className="finding-details-row">
                    <td />
                    <td>
                      <FindingDetails finding={finding} />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      ))}
    </table>
  )
}

function GroupHeader({ module, count }: { module: ModuleName; count: number }) {
  return (
    <tr className="group-row">
      <th scope="rowgroup" colSpan={2}>
        {MODULE_LABELS[module]} <span className="group-count">{plural(count, 'finding')}</span>
      </th>
    </tr>
  )
}

function FindingDetails({ finding }: { finding: Finding }) {
  const entries = Object.entries(finding.details)
  return (
    <div className="finding-details">
      <p>{finding.description}</p>
      {entries.length > 0 && (
        <dl className="details-list">
          {entries.map(([key, value]) => (
            <Fragment key={key}>
              <dt>{humanize(key)}</dt>
              <dd>
                <DetailValue value={value} />
              </dd>
            </Fragment>
          ))}
        </dl>
      )}
    </div>
  )
}

// details differs per module (data contract 10.1), so values are shown generically
function DetailValue({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === '') return <span className="muted">None</span>
  if (Array.isArray(value) && value.every((v) => typeof v !== 'object')) {
    return value.length === 0 ? <span className="muted">None</span> : <span className="mono">{value.join(', ')}</span>
  }
  if (typeof value === 'object') return <pre className="details-json">{JSON.stringify(value, null, 2)}</pre>
  return <span className="mono">{String(value)}</span>
}

function humanize(key: string): string {
  const text = key.replaceAll('_', ' ')
  return text.charAt(0).toUpperCase() + text.slice(1)
}

export default FindingsTable
