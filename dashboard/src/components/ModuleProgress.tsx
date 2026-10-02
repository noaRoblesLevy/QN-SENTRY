import type { ModuleRun } from '../types'
import { MODULE_LABELS } from '../lib/labels'
import StatusBadge from './StatusBadge'

/** Progress per module while a scan runs (issue #14), with errors and warnings (#32) */
function ModuleProgress({ modules }: { modules: ModuleRun[] }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th scope="col">Module</th>
          <th scope="col">Status</th>
          <th scope="col" className="numeric">
            Findings
          </th>
        </tr>
      </thead>
      <tbody>
        {modules.map((run) => (
          <tr key={run.module}>
            <td>{MODULE_LABELS[run.module]}</td>
            <td>
              <StatusBadge kind="module" status={run.status} hasWarnings={run.warnings.length > 0} />
              {run.error && <p className="module-error mono">{run.error}</p>}
              {run.warnings.length > 0 && (
                <ul className="module-warnings" aria-label={`Warnings of ${MODULE_LABELS[run.module]}`}>
                  {run.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              )}
            </td>
            <td className="numeric">{run.status === 'completed' ? run.finding_count : '–'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default ModuleProgress
