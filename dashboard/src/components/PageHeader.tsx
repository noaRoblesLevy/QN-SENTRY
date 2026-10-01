import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { ChevronRight } from 'lucide-react'
import './PageHeader.css'

type Crumb = { label: string; to?: string }

type PageHeaderProps = {
  title: ReactNode
  breadcrumbs?: Crumb[]
  meta?: ReactNode
  actions?: ReactNode
}

function PageHeader({ title, breadcrumbs = [], meta, actions }: PageHeaderProps) {
  return (
    <header className="page-header">
      {breadcrumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="breadcrumbs">
          {breadcrumbs.map((crumb, index) => (
            <span key={`${crumb.label}-${index}`} className="breadcrumb">
              {index > 0 && <ChevronRight size={16} strokeWidth={1.5} aria-hidden="true" />}
              {crumb.to ? <Link to={crumb.to}>{crumb.label}</Link> : <span aria-current="page">{crumb.label}</span>}
            </span>
          ))}
        </nav>
      )}
      <div className="page-header-row">
        <div>
          <h1 className="page-title">{title}</h1>
          {meta && <div className="page-meta">{meta}</div>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
    </header>
  )
}

export default PageHeader
