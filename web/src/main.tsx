// ABOUTME: Browser entry point — mounts the fleet page into the served shell.
// ABOUTME: Nothing but mounting happens here; all behavior lives in App and its components.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { SessionProvider } from './session'
import './styles.css'

const root = document.getElementById('root')
if (!root) throw new Error('missing #root')
createRoot(root).render(
  <StrictMode>
    <SessionProvider>
      <App />
    </SessionProvider>
  </StrictMode>,
)
