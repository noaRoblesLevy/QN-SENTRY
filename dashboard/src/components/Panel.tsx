import type { ReactNode } from 'react'
import './Panel.css'

type PanelProps = {
  title: string
  meta?: ReactNode
  actions?: ReactNode
  children: ReactNode
  /** Remove the inner padding, for tables that run edge to edge */
  flush?: boolean
}

function Panel({ title, meta, actions, children, flush = false }: PanelProps) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div className="panel-heading">
          <h2 className="panel-title">{title}</h2>
          {meta && <span className="panel-meta">{meta}</span>}
        </div>
        {actions && <div className="panel-actions">{actions}</div>}
      </div>
      <div className={flush ? 'panel-body-flush' : 'panel-body'}>{children}</div>
    </section>
  )
}

export default Panel
