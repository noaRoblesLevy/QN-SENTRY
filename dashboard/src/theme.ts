export type Theme = 'dark' | 'light'

// Same key as the inline script in index.html, which applies the theme before React loads
export const THEME_STORAGE_KEY = 'qn-sentry-theme'

export function getCurrentTheme(): Theme {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'
}

export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch {
    // Storage can be blocked (e.g. private mode); the theme still works for this visit
  }
}
