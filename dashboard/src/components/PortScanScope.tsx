import { useState } from 'react'
import { Save } from 'lucide-react'
import { api } from '../api'
import { useAsync } from '../hooks/useAsync'
import type { Address, Domain } from '../types'
import Button from './Button'
import { ErrorState, LoadingState } from './States'
import './PortScanScope.css'

/**
 * Which addresses of a verified domain may get a port scan (#81).
 *
 * The TXT record proves control of the domain, not of the servers behind it: a host can
 * point to shared hosting (e.g. Vercel) whose ports belong to someone else. So every
 * address is unchecked until the user confirms it is theirs.
 */
function PortScanScope({ domain }: { domain: Domain }) {
  const { data, error, loading, reload } = useAsync(`addresses-${domain.id}`, () => api.getAddresses(domain.id))

  if (loading) return <LoadingState label={`Loading the addresses of ${domain.name}`} />
  if (!data) return <ErrorState error={error ?? new Error('Could not load the addresses')} onRetry={reload} />
  return <AddressForm key={approvedKey(data)} domain={domain} addresses={data} />
}

function approvedKey(addresses: Address[]): string {
  return addresses
    .filter((a) => a.approved)
    .map((a) => a.ip)
    .join(',')
}

function AddressForm({ domain, addresses }: { domain: Domain; addresses: Address[] }) {
  const [current, setCurrent] = useState(addresses)
  const [checked, setChecked] = useState(() => new Set(addresses.filter((a) => a.approved).map((a) => a.ip)))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string>()
  const [saved, setSaved] = useState(false)

  const approved = new Set(current.filter((a) => a.approved).map((a) => a.ip))
  const changed = checked.size !== approved.size || [...checked].some((ip) => !approved.has(ip))

  function toggle(ip: string) {
    setSaved(false)
    setChecked((previous) => {
      const next = new Set(previous)
      if (next.has(ip)) next.delete(ip)
      else next.add(ip)
      return next
    })
  }

  async function save() {
    setSaving(true)
    setError(undefined)
    try {
      // Keep the order of the list, so the request is predictable
      const result = await api.setPortScanAddresses(
        domain.id,
        current.map((a) => a.ip).filter((ip) => checked.has(ip)),
      )
      setCurrent(result)
      setChecked(new Set(result.filter((a) => a.approved).map((a) => a.ip)))
      setSaved(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong. Try again.')
    } finally {
      setSaving(false)
    }
  }

  if (current.length === 0) {
    return (
      <p className="port-scan-empty muted">
        No addresses yet: run a scan of <span className="mono">{domain.name}</span> first, the attack surface module
        finds the addresses of its hosts.
      </p>
    )
  }

  return (
    <div className="port-scan">
      <ul className="port-scan-list">
        {current.map((address) => {
          const id = `port-scan-${domain.id}-${address.ip}`
          return (
            <li key={address.ip}>
              <input
                id={id}
                type="checkbox"
                checked={checked.has(address.ip)}
                onChange={() => toggle(address.ip)}
                disabled={saving}
              />
              <label htmlFor={id}>
                <span className="mono">{address.ip}</span>
                <span className="muted">
                  {address.hosts.length > 0
                    ? address.hosts.join(', ')
                    : 'not found in the latest scan anymore; uncheck it to withdraw the approval'}
                </span>
                <span className="port-scan-statement">I own or manage this server and may scan its ports</span>
              </label>
            </li>
          )
        })}
      </ul>
      <div className="port-scan-actions">
        <Button
          icon={<Save size={16} strokeWidth={1.5} aria-hidden="true" />}
          onClick={save}
          disabled={saving || !changed}
        >
          {saving ? 'Saving' : 'Save'}
        </Button>
        {saved && !changed && (
          <span className="muted" role="status">
            Saved: {approved.size === 0 ? 'no address' : `${approved.size} address${approved.size === 1 ? '' : 'es'}`} may
            get a port scan
          </span>
        )}
      </div>
      {error && (
        <p className="field-error" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}

export default PortScanScope
