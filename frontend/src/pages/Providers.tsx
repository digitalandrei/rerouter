/**
 * /providers — governed by docs/doctrine.md §5.3/§6 and docs/security.md.
 *
 * Reroute provider CRUD (Cloudflare accounts, BGP upstreams, scrubbing
 * centers) with reachability shown prominently. Credential handling: secrets
 * are write-only from the UI; the API exposes metadata only
 * (view_credentials_metadata) — plaintext secrets never round-trip to the
 * browser. Encryption at rest is the controller's job (AES-256-GCM).
 */
import { useEffect, useState } from "react";
import { api, type Provider } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Providers() {
  const [providers, setProviders] = useState<Provider[]>([]);

  useEffect(() => {
    api.providers.list().then(setProviders).catch(() => setProviders([]));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Reroute providers</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Providers</CardTitle>
        </CardHeader>
        <CardContent>
          {providers.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No providers yet (or API not reachable). Provider CRUD +
              credential-metadata view placeholder.
            </p>
          ) : (
            <ul className="divide-y">
              {providers.map((provider) => (
                <li
                  key={provider.id}
                  className="flex items-center gap-3 py-3 text-sm"
                >
                  <span className="font-medium">{provider.name}</span>
                  <Badge variant="secondary">{provider.kind}</Badge>
                  <span className="flex-1" />
                  <Badge
                    variant={
                      provider.reachability === "ok" ? "default" : "destructive"
                    }
                  >
                    {provider.reachability}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
