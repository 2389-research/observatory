// ABOUTME: Session context: who the caller is, and whether mutations carry a CSRF token.
// ABOUTME: Also wires the mutation client's token provider, so there is one source of truth.
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { getJSON, setCSRFProvider, ApiFailure } from './api'

/** What GET /auth/session answers. `csrf_token` is absent when auth is off. */
interface SessionBody {
  owner: string
  method: string
  expires_at?: string
  csrf_token?: string
}

/**
 * `unknown` is the honest state when the probe itself failed: the caller may
 * well be signed in and unable to prove it, which is not the same as signed out.
 */
export type SessionStatus = 'loading' | 'ready' | 'signed_out' | 'unknown'

export interface Session {
  status: SessionStatus
  owner?: string
  method?: string
  csrfToken?: string
  expiresAt?: string
  refresh: () => Promise<void>
}

const SessionContext = createContext<Session>({
  status: 'loading',
  refresh: async () => {},
})

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<Omit<Session, 'refresh'>>({ status: 'loading' })

  const refresh = useCallback(async () => {
    try {
      const body = await getJSON<SessionBody>('/auth/session')
      setState({
        status: 'ready',
        owner: body.owner,
        method: body.method,
        csrfToken: body.csrf_token,
        expiresAt: body.expires_at,
      })
    } catch (e) {
      if (e instanceof ApiFailure && e.status === 401) {
        setState({ status: 'signed_out' })
        return
      }
      setState({ status: 'unknown' })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  // The mutation client reads the token through this provider rather than
  // taking it as an argument, so no call site can forget it.
  useEffect(() => {
    setCSRFProvider(() => ({ method: state.method ?? 'none', csrfToken: state.csrfToken }), refresh)
  }, [state.method, state.csrfToken, refresh])

  return <SessionContext.Provider value={{ ...state, refresh }}>{children}</SessionContext.Provider>
}

export function useSession(): Session {
  return useContext(SessionContext)
}
