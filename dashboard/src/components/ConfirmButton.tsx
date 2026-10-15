import { useState, type ReactNode } from 'react'
import Button from './Button'
import './ConfirmButton.css'

type ConfirmButtonProps = {
  /** Label of the trigger button */
  label: string
  /** What will happen, shown when the user is asked to confirm */
  message: string
  /** Label of the confirm button (default "Delete") */
  confirmLabel?: string
  icon?: ReactNode
  /** Runs on confirm; throw an Error with a user-facing message to show it inline */
  onConfirm: () => Promise<void>
}

/**
 * A button that asks for confirmation inline before running a destructive action (#16).
 * On success the parent navigates or reloads; an error from `onConfirm` (e.g. the 409 while
 * a scan runs) is shown next to the button.
 */
function ConfirmButton({ label, message, confirmLabel = 'Delete', icon, onConfirm }: ConfirmButtonProps) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()

  async function run() {
    setBusy(true)
    setError(undefined)
    try {
      await onConfirm()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong. Try again.')
      setBusy(false)
      setConfirming(false)
    }
  }

  if (!confirming) {
    return (
      <span className="confirm-button">
        <Button variant="ghost" className="button-danger" icon={icon} onClick={() => setConfirming(true)}>
          {label}
        </Button>
        {error && (
          <span className="field-error" role="alert">
            {error}
          </span>
        )}
      </span>
    )
  }

  return (
    <span className="confirm-button confirm-button-open" role="group" aria-label={label}>
      <span className="confirm-message">{message}</span>
      <Button variant="ghost" className="button-danger" onClick={run} disabled={busy}>
        {busy ? 'Deleting...' : confirmLabel}
      </Button>
      <Button variant="ghost" onClick={() => setConfirming(false)} disabled={busy}>
        Cancel
      </Button>
    </span>
  )
}

export default ConfirmButton
