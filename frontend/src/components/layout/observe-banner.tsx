import { useEffect, useState } from 'react'
import { TriangleAlert } from 'lucide-react'
import { api, type SystemStatus } from '@/lib/api'

// Persistent operating-mode banner. Polls GET /api/status on an interval (not
// once per mount) so an admin flipping observe<->enforce is reflected in every
// open tab, and renders a DISTINCT degraded banner when the API is unreachable
// rather than silently showing nothing — "we don't know the mode" must not look
// the same as "safe in observe". docs/doctrine.md §5.3 / §8.
export function ObserveBanner() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let active = true
    const load = () => {
      api
        .status()
        .then((s) => {
          if (!active) return
          setStatus(s)
          setFailed(false)
        })
        .catch(() => {
          if (active) setFailed(true)
        })
    }
    load()
    const timer = setInterval(load, 30_000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [])

  // API unreachable: we cannot vouch for the current mode — say so loudly rather
  // than rendering nothing (which is indistinguishable from "safe").
  if (failed) {
    return (
      <div className="flex items-center gap-2 border-b border-red-500 bg-red-50 px-4 py-2 text-sm font-semibold text-red-800">
        <TriangleAlert className="h-4 w-4 shrink-0" />
        <span>
          MODE UNKNOWN — the controller API is unreachable. Do not assume reroutes
          are disabled; verify controller status before acting.
        </span>
      </div>
    )
  }

  if (!status || status.operating_mode === 'enforce') return null

  return (
    <div className="flex items-center gap-2 border-b border-yellow-400 bg-yellow-50 px-4 py-2 text-sm font-semibold text-yellow-800">
      <TriangleAlert className="h-4 w-4 shrink-0" />
      <span>
        OBSERVE MODE — read-only / alert-only. No reroutes will execute
        (automatic or manual). Alerts show the actions that WOULD run.
      </span>
    </div>
  )
}
