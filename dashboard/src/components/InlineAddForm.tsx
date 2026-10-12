import { useState, type FormEvent } from 'react'
import { Plus } from 'lucide-react'
import Button from './Button'
import TextInput from './TextInput'
import './InlineAddForm.css'

type InlineAddFormProps = {
  label: string
  placeholder: string
  buttonLabel: string
  hint?: string
  /** A statement the user must tick before adding, e.g. permission to scan (#3) */
  confirmation?: string
  /** Throws an Error with a user-facing message when adding fails */
  onAdd: (value: string, confirmed: boolean) => Promise<void>
}

/** One text field with an add button, e.g. "Add client" or "Add domain" */
function InlineAddForm({ label, placeholder, buttonLabel, hint, confirmation, onAdd }: InlineAddFormProps) {
  const [value, setValue] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState<string>()
  const [saving, setSaving] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!value.trim()) {
      setError(`Enter a ${label.toLowerCase()}.`)
      return
    }
    if (confirmation && !confirmed) {
      setError('Tick the confirmation below first.')
      return
    }
    setSaving(true)
    setError(undefined)
    try {
      await onAdd(value, confirmed)
      setValue('')
      setConfirmed(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong. Try again.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="inline-add-form" onSubmit={handleSubmit} noValidate>
      <TextInput
        className="inline-add-field"
        label={label}
        placeholder={placeholder}
        value={value}
        hint={hint}
        error={error}
        onChange={(event) => setValue(event.target.value)}
        disabled={saving}
      />
      <Button type="submit" icon={<Plus size={16} strokeWidth={1.5} aria-hidden="true" />} disabled={saving}>
        {buttonLabel}
      </Button>
      {confirmation && (
        <label className="inline-add-confirmation">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
            disabled={saving}
          />
          {confirmation}
        </label>
      )}
    </form>
  )
}

export default InlineAddForm
