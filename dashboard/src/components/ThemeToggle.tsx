import { useState } from 'react'
import { Moon, Sun } from 'lucide-react'
import { applyTheme, getCurrentTheme, type Theme } from '../theme'
import './ThemeToggle.css'

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(getCurrentTheme)

  const nextTheme: Theme = theme === 'dark' ? 'light' : 'dark'
  const Icon = nextTheme === 'light' ? Sun : Moon

  function toggle() {
    applyTheme(nextTheme)
    setTheme(nextTheme)
  }

  return (
    <button type="button" className="theme-toggle" onClick={toggle}>
      <Icon size={16} strokeWidth={1.5} aria-hidden="true" />
      {nextTheme === 'light' ? 'Light theme' : 'Dark theme'}
    </button>
  )
}

export default ThemeToggle
