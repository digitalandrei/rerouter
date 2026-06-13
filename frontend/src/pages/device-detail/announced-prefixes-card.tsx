import { useCallback, useEffect, useState } from "react";
import { Globe } from "lucide-react";
import { api, type BgpNetwork } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Announced BGP prefixes (network statements), SSH-discovered + daily-refreshed.
 *  Feeds the blackhole prefix picker and the null-route parent. Reloads on
 *  refreshKey (the page's single Refresh runs the discovery). */
export function AnnouncedPrefixesCard({
  deviceId,
  refreshKey,
}: {
  deviceId: number;
  refreshKey: number;
}) {
  const [networks, setNetworks] = useState<BgpNetwork[] | null>(null);

  const load = useCallback(() => {
    api.devices
      .bgpNetworks(deviceId)
      .then(setNetworks)
      .catch(() => setNetworks([]));
  }, [deviceId]);
  useEffect(() => {
    load();
  }, [load, refreshKey]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Globe className="size-4 text-muted-foreground" />
          Announced prefixes
          <Badge variant="outline" className="ml-1 font-normal text-muted-foreground">
            via SSH · daily
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {networks === null ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : networks.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No announced prefixes discovered yet — Refresh (needs SSH).
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {networks.map((n) => (
              <code key={n.id} className="rounded-md border border-border px-2 py-1 text-xs">
                {n.prefix}
              </code>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
