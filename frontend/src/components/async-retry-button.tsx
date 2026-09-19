import { useState } from "react";
import { Button } from "@/components/ui/button";

export function AsyncRetryButton({ onRetry, label = "Try again" }: { onRetry: () => void | Promise<unknown>; label?: string }) {
  const [loading, setLoading] = useState(false);
  return <Button size="sm" variant="outline" loading={loading} loadingLabel="Retrying…" onClick={() => { if (loading) return; setLoading(true); void Promise.resolve().then(onRetry).finally(() => setLoading(false)); }}>{label}</Button>;
}
