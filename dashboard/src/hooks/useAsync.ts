import { useCallback, useEffect, useEffectEvent, useState } from 'react'

type Options<T> = {
  /** After each successful load: milliseconds until the next load, or null to stop polling */
  pollInterval?: (data: T) => number | null
}

type Result<T> = {
  data: T | undefined
  error: Error | undefined
  loading: boolean
  /** Load again without clearing what is on screen (e.g. after adding something) */
  reload: () => void
}

/**
 * Loads data when `key` changes, e.g. useAsync(`scan-${id}`, () => api.getScan(id)).
 * The key says which data this is, so a new id starts a new load.
 */
export function useAsync<T>(key: string, load: () => Promise<T>, options: Options<T> = {}): Result<T> {
  const [state, setState] = useState<{ key: string; data?: T; error?: Error }>()
  const [reloadCount, setReloadCount] = useState(0)

  const runLoad = useEffectEvent(load)
  const nextPoll = useEffectEvent((data: T) => options.pollInterval?.(data) ?? null)

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    function run() {
      runLoad().then(
        (data) => {
          if (cancelled) return
          setState({ key, data })
          const wait = nextPoll(data)
          if (wait !== null) timer = setTimeout(run, wait)
        },
        (error: unknown) => {
          if (cancelled) return
          setState((previous) => ({
            key,
            data: previous?.key === key ? previous.data : undefined,
            error: error instanceof Error ? error : new Error(String(error)),
          }))
        },
      )
    }

    run()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [key, reloadCount])

  const reload = useCallback(() => setReloadCount((n) => n + 1), [])
  const current = state?.key === key ? state : undefined

  return {
    data: current?.data,
    error: current?.error,
    loading: current === undefined,
    reload,
  }
}
