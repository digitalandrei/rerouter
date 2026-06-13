import { useEffect, useState } from 'react'
import { TriangleAlert } from 'lucide-react'
import { api, type SystemStatus } from '@/lib/api'

// Persistent operating-mode banner. Polls GET /api/status once on mount and
// renders prominently whenever the controller is NOT in enforce mode — i.e.
// in the shipped `observe` default, where no reroute (manual or automatic)
// executes and alerts only carry the would-run plan (docs/doctrine.md §8).
export function ObserveBanner() {
  const [status, setStatus] = useState<SystemStatus | null>(null)

  useEffect(() => {
    api
      .status()
      .then(setStatus)
      .catch(() => setStatus(null))
  }, [])

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
