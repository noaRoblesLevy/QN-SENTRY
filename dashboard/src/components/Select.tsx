import { useId, type SelectHTMLAttributes } from 'react'
import './TextInput.css'

type SelectProps = SelectHTMLAttributes<HTMLSelectElement> & {
  label: string
  options: { value: string; label: string }[]
}

function Select({ label, options, className = '', ...rest }: SelectProps) {
  const id = useId()
  return (
    <div className={`field ${className}`}>
      <label htmlFor={id} className="field-label">
        {label}
      </label>
      <select id={id} className="field-input" {...rest}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  )
}

export default Select
