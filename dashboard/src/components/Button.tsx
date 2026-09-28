import type { ButtonHTMLAttributes, ReactNode } from 'react'
import './Button.css'

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost'
  icon?: ReactNode
}

// At most one primary button per view (house style)
function Button({ variant = 'secondary', icon, children, className = '', type = 'button', ...rest }: ButtonProps) {
  return (
    <button type={type} className={`button button-${variant} ${className}`} {...rest}>
      {icon}
      {children}
    </button>
  )
}

export default Button
