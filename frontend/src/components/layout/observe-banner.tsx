import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, RefreshCw, ShieldAlert } from 'lucide-react'
import { api, type SystemSettings, type SystemStatus } from '@/lib/api'
import { Button } from '@/components/ui/button'

// Persistent operating-mode banner. Polls GET /api/status on an interval (not
// once per mount) so an admin flipping observe<->enforce is reflected in every
// open tab, and renders a DISTINCT degraded banner when the API is unreachable
// rather than silently showing nothing — "we don't know the mode" must not look
// the same as "safe in observe". docs/doctrine.md §5.3 / §8.
export function ObserveBanner({ connectionIssue, onRetryConnection }: { connectionIssue?: string | null; onRetryConnection?: () => void }) {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [settings, setSettings] = useState<SystemSettings | null>(null)
  const [failed, setFailed] = useState(false)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)

  useEffect(() => {
    let active = true
    const load = async () => {
      const [statusResult, settingsResult] = await Promise.allSettled([api.status(), api.settings.get()])
      if (!active) return
      if (statusResult.status === 'fulfilled') setStatus(statusResult.value)
      if (settingsResult.status === 'fulfilled') setSettings(settingsResult.value)
      const complete = statusResult.status === 'fulfilled' && settingsResult.status === 'fulfilled'
      setFailed(!complete)
      if (complete) setUpdatedAt(new Date())
    }
    void load()
    const timer = setInterval(() => void load(), 30_000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [])

  const mode = status?.operating_mode ?? settings?.operating_mode
  const automation = settings?.automatic_actions_enabled
  const maintenance = settings?.global_lock
  const unavailable = failed || Boolean(connectionIssue)
  const Icon = unavailable ? AlertTriangle : mode === 'enforce' ? ShieldAlert : CheckCircle2

  return (
    <div role="status" aria-live="polite" className={`flex flex-wrap items-center gap-x-4 gap-y-2 border-b px-4 py-2 text-sm ${unavailable ? 'border-red-400 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-100' : mode === 'enforce' ? 'border-orange-400 bg-orange-50 text-orange-950 dark:border-orange-800 dark:bg-orange-950/40 dark:text-orange-100' : 'border-amber-400 bg-amber-50 text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100'}`}>
      <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
      <strong>{mode ? `${mode.toUpperCase()} mode` : 'MODE UNKNOWN'}</strong>
      <span>Automation: {automation === undefined ? 'unknown' : automation ? 'enabled' : 'disabled'}</span>
      <span>Maintenance lock: {maintenance === undefined ? 'unknown' : maintenance ? 'active' : 'clear'}</span>
      <span className="min-w-0 text-xs opacity-80">{mode === 'observe' ? 'Automatic response is disabled. Manual runs remain available after explicit preview and confirmation.' : mode === 'enforce' ? 'Automatic response can run only when the master switch and every safety gate allow it. Manual runs still require preview and confirmation.' : 'Verify controller state before making an operational decision.'}</span>
      <span className="ml-auto text-xs opacity-80">{unavailable ? 'Connection interrupted; showing last known state.' : updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : 'Connecting…'}</span>
      {unavailable && onRetryConnection && <Button type="button" size="sm" variant="outline" className="h-7" onClick={onRetryConnection}><RefreshCw className="mr-1 h-3.5 w-3.5" /> Retry</Button>}
    </div>
  )
}
