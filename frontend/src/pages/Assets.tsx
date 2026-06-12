/**
 * /assets — governed by docs/asset-enrollment.md and docs/doctrine.md §5.3.
 *
 * Lists protected assets with reachability and telemetry freshness shown
 * prominently (live / cached / degraded / unknown). Newly-discovered assets
 * stay clearly marked as unacknowledged: no automatic action may target them
 * until acknowledged (docs/doctrine.md §8). Drag-and-drop monitored-asset
 * builder lands here.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Asset } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    api.assets.list().then(setAssets).catch(() => setAssets([]));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Protected assets</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Assets</CardTitle>
        </CardHeader>
        <CardContent>
          {assets.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No assets yet (or API not reachable). Asset CRUD + drag-and-drop
              monitored-asset builder placeholder.
            </p>
          ) : (
            <ul className="divide-y">
              {assets.map((asset) => (
                <li
                  key={asset.id}
                  className="flex items-center gap-3 py-3 text-sm"
                >
                  <Link
                    to={`/assets/${asset.id}`}
                    className="font-medium underline-offset-4 hover:underline"
                  >
                    {asset.name}
                  </Link>
                  <code className="text-xs text-muted-foreground">
                    {asset.value}
                  </code>
                  <span className="flex-1" />
                  <Badge
                    variant={
                      asset.telemetry_freshness === "live"
                        ? "default"
                        : "destructive"
                    }
                  >
                    {asset.telemetry_freshness}
                  </Badge>
                  {!asset.acknowledged && (
                    <Badge variant="destructive">unacknowledged</Badge>
                  )}
                  {asset.locked && <Badge variant="destructive">locked</Badge>}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
