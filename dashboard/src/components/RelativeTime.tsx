import { formatAbsolute, formatRelative } from '../lib/format'

/** "4 h ago", with the absolute UTC time on hover (house style) */
function RelativeTime({ iso }: { iso: string }) {
  return (
    <time dateTime={iso} title={formatAbsolute(iso)}>
      {formatRelative(iso)}
    </time>
  )
}

export default RelativeTime
