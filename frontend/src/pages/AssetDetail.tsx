/**
 * /assets/:id — governed by docs/asset-enrollment.md, docs/telemetry-model.md
 * and docs/doctrine.md §5.3.
 *
 * Single-asset view: live telemetry (GET /api/assets/{id}/live), reachability,
 * lock state, the rules attached to this asset, and the action history shown
 * NEAR the asset (doctrine: "show action history near every rule and asset").
 * Also hosts the telemetry test (POST .../test/telemetry) and rediscovery
 * (POST .../rediscover) actions.
 */
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, type Asset } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>();
  const assetId = Number(id);
  const [asset, setAsset] = useState<Asset | null>(null);

  useEffect(() => {
    if (!Number.isFinite(assetId)) return;
    api.assets.get(assetId).then(setAsset).catch(() => setAsset(null));
  }, [assetId]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold tracking-tight">
          {asset?.name ?? `Asset #${id}`}
        </h1>
        {asset && (
          <Badge
            variant={
              asset.telemetry_freshness === "live" ? "default" : "destructive"
            }
          >
            {asset.telemetry_freshness}
          </Badge>
        )}
        {asset?.locked && <Badge variant="destructive">locked</Badge>}
      </div>

      <div className="flex gap-2">
        <Button
          variant="outline"
          onClick={() => void api.assets.testTelemetry(assetId)}
        >
          Test telemetry
        </Button>
        <Button
          variant="outline"
          onClick={() => void api.assets.rediscover(assetId)}
        >
          Rediscover
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Live telemetry</CardTitle>
          <CardDescription>
            Placeholder — GET /api/assets/{id}/live chart with explicit
            freshness state.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Not implemented yet.
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Action history</CardTitle>
          <CardDescription>
            Placeholder — reroute/detection history for this asset, shown next
            to the asset per doctrine.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Not implemented yet.
        </CardContent>
      </Card>
    </div>
  );
}
