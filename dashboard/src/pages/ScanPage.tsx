import { useState } from 'react'
import { useParams } from 'react-router'
import { FileDown } from 'lucide-react'
import { api, reportUrl } from '../api'
import FindingsTable from '../components/FindingsTable'
import ModuleProgress from '../components/ModuleProgress'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import RelativeTime from '../components/RelativeTime'
import Select from '../components/Select'
import RiskBadge from '../components/RiskBadge'
import SeverityBadge from '../components/SeverityBadge'
import StatPanel from '../components/StatPanel'
import { EmptyState, ErrorState, LoadingState } from '../components/States'
import StatusBadge from '../components/StatusBadge'
import { useAsync } from '../hooks/useAsync'
import { plural } from '../lib/format'
import { isScanActive, MODULE_LABELS, MODULES, SEVERITIES, SEVERITY_LABELS } from '../lib/labels'
import NotFoundPage from './NotFoundPage'
import './ScanPage.css'

// Data contract 10.5.1: poll every 5 seconds while the scan is queued or running
const POLL_MS = 5_000
const ALL = 'all'

function ScanPage() {
  const scanId = Number(useParams().scanId)
  if (!Number.isInteger(scanId)) return <NotFoundPage />
  return <ScanView scanId={scanId} />
}

function ScanView({ scanId }: { scanId: number }) {
  const { data, error, loading, reload } = useAsync(
    `scan-${scanId}`,
    async () => {
      const [scan, findings] = await Promise.all([api.getScan(scanId), api.getFindings(scanId)])
      return { scan, findings }
    },
    { pollInterval: ({ scan }) => (isScanActive(scan.status) ? POLL_MS : null) },
  )
  const [moduleFilter, setModuleFilter] = useState(ALL)
  const [severityFilter, setSeverityFilter] = useState(ALL)

  if (loading) return <LoadingState label="Loading scan" />
  if (!data) {
    return (
      <>
        <PageHeader title={`Scan #${scanId}`} breadcrumbs={[{ label: 'Clients', to: '/' }]} />
        <Panel title="Could not load this scan">
          <ErrorState error={error ?? new Error('Scan not found')} onRetry={reload} />
        </Panel>
      </>
    )
  }

  const { scan, findings } = data
  // Modules that completed without warnings and are not a placeholder (data contract 10.7)
  const placeholders = new Set(findings.filter((f) => f.type === 'placeholder').map((f) => f.module))
  const fullyChecked = scan.modules.filter(
    (m) => m.status === 'completed' && m.warnings.length === 0 && !placeholders.has(m.module),
  ).length
  const active = isScanActive(scan.status)
  const report = reportUrl(scan.id)
  const visible = findings.filter(
    (f) => (moduleFilter === ALL || f.module === moduleFilter) && (severityFilter === ALL || f.severity === severityFilter),
  )

  return (
    <>
      <PageHeader
        title={
          <>
            Scan of <span className="scan-domain">{scan.domain}</span>
          </>
        }
        breadcrumbs={[{ label: 'Clients', to: '/' }, { label: `Scan #${scan.id}` }]}
        meta={
          <>
            <StatusBadge kind="scan" status={scan.status} />
            <span>
              Started <RelativeTime iso={scan.created_at} />
            </span>
          </>
        }
        actions={
          // The report exists once the scan has finished, and not for a failed scan (issue #17)
          !active &&
          scan.status !== 'failed' &&
          report && (
            <a className="button button-primary" href={report} download>
              <FileDown size={16} strokeWidth={1.5} aria-hidden="true" />
              Download report
            </a>
          )
        }
      />

      {/* A failed poll keeps the last data on screen and shows why it is not updating */}
      {error && (
        <p className="scan-warning" role="alert">
          Could not refresh this scan: {error.message}
        </p>
      )}

      <div className="stat-grid">
        {/* Risk score (#19): computed by the backend once the scan has finished */}
        <div className="stat-panel">
          <div className="stat-label">Risk score</div>
          <div className="stat-value">{scan.risk_score ?? '-'}</div>
          <RiskBadge risk={scan} showScore={false} />
          {scan.risk_complete === false && (
            <div className="stat-note">
              Based on {fullyChecked} of {scan.modules.length} modules without problems
            </div>
          )}
        </div>
        <StatPanel label="Findings" value={findings.length} />
        {SEVERITIES.map((severity) => (
          <StatPanel
            key={severity}
            label={<SeverityBadge severity={severity} />}
            value={findings.filter((f) => f.severity === severity).length}
          />
        ))}
      </div>

      <Panel
        title="Progress"
        meta={active ? 'Updates every 5 seconds. A full scan takes 10 to 30 minutes.' : undefined}
        flush
      >
        <ModuleProgress modules={scan.modules} />
      </Panel>

      <Panel
        title="Findings"
        meta={plural(visible.length, 'finding')}
        actions={
          <>
            <Select
              label="Module"
              value={moduleFilter}
              onChange={(event) => setModuleFilter(event.target.value)}
              options={[{ value: ALL, label: 'All modules' }, ...MODULES.map((m) => ({ value: m, label: MODULE_LABELS[m] }))]}
            />
            <Select
              label="Severity"
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
              options={[
                { value: ALL, label: 'All severities' },
                ...SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABELS[s] })),
              ]}
            />
          </>
        }
        flush
      >
        {visible.length > 0 ? (
          <FindingsTable findings={visible} />
        ) : findings.length > 0 ? (
          <EmptyState title="No findings match these filters." />
        ) : active ? (
          <EmptyState title="No findings yet">Findings appear here as each module finishes.</EmptyState>
        ) : (
          <EmptyState title="No findings">This scan found nothing an attacker could use.</EmptyState>
        )}
      </Panel>
    </>
  )
}

export default ScanPage
