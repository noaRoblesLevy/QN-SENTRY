import { useId, type InputHTMLAttributes } from 'react'
import './TextInput.css'

type TextInputProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string
  hint?: string
  error?: string
}

function TextInput({ label, hint, error, className = '', ...rest }: TextInputProps) {
  const id = useId()
  const messageId = `${id}-message`
  const message = error ?? hint

  return (
    <div className={`field ${className}`}>
      <label htmlFor={id} className="field-label">
        {label}
      </label>
      <input
        id={id}
        className={`field-input ${error ? 'field-input-error' : ''}`}
        aria-invalid={error ? true : undefined}
        aria-describedby={message ? messageId : undefined}
        {...rest}
      />
      {message && (
        <p id={messageId} className={error ? 'field-error' : 'field-hint'}>
          {message}
        </p>
      )}
    </div>
  )
}

export default TextInput
