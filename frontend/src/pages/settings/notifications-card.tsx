/**
 * Notification settings: email recipients + Microsoft Teams webhooks, with
 * per-event routing and a test-send. All writes require `manage_alerts`.
 *
 * Teams webhook URLs are write-only — the API never returns them (they are stored
 * encrypted). Leaving the event-type list empty routes ALL events to that target.
 */
import { useCallback, useState } from "react";
import { toast } from "sonner";
import {
  api,
  ApiError,
} from "@/lib/api";
import { eventTypeLabel } from "@/lib/labels";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/lib/auth";
import { useResource } from "@/lib/resource-state";
import { DataState } from "@/components/data-state";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

function EventPicker({
  all,
  selected,
  onToggle,
  disabled = false,
}: {
  all: string[];
  selected: string[];
  onToggle: (e: string) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-1">
      <p className="text-xs text-muted-foreground">
        Events to route ({selected.length === 0 ? "all events" : `${selected.length} selected`})
      </p>
      <div className="flex flex-wrap gap-x-3 gap-y-1">
        {all.map((e) => (
          <label key={e} className="flex items-center gap-1 text-xs font-normal">
            <input
              type="checkbox"
              disabled={disabled}
              checked={selected.includes(e)}
              onChange={() => onToggle(e)}
            />
            {eventTypeLabel(e)}
          </label>
        ))}
      </div>
    </div>
  );
}

function eventSummary(events: string[]): string {
  return events.includes("*") || events.length === 0
    ? "all events"
    : events.map(eventTypeLabel).join(", ");
}

export function NotificationsCard() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("manage_alerts");
  const resource = useResource(useCallback(async (_signal: AbortSignal) => {
    const [eventTypes, recipients, webhooks] = await Promise.all([api.notifications.eventTypes(), api.notifications.recipients(), api.notifications.webhooks()]);
    return { eventTypes, recipients, webhooks };
  }, []), []);

  const [email, setEmail] = useState("");
  const [emailEvents, setEmailEvents] = useState<string[]>([]);
  const [hookName, setHookName] = useState("");
  const [hookUrl, setHookUrl] = useState("");
  const [hookEvents, setHookEvents] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);

  function toggle(list: string[], set: (v: string[]) => void, e: string) {
    set(list.includes(e) ? list.filter((x) => x !== e) : [...list, e]);
  }

  async function addRecipient() {
    if (!email.includes("@")) {
      toast.error("Enter a valid email");
      return;
    }
    setBusy("recipient-add"); setMutationError(null);
    try {
      await api.notifications.addRecipient({ email: email.trim(), event_types: emailEvents });
      toast.success(`Added ${email.trim()}`);
      setEmail("");
      setEmailEvents([]);
      resource.retry();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to add recipient");
      setMutationError(err instanceof ApiError ? err.message : "Failed to add recipient");
    } finally {
      setBusy(null);
    }
  }

  async function addWebhook() {
    if (!hookName.trim() || !hookUrl.startsWith("https://")) {
      toast.error("Name and an https:// webhook URL are required");
      return;
    }
    setBusy("webhook-add"); setMutationError(null);
    try {
      await api.notifications.addWebhook({
        name: hookName.trim(),
        url: hookUrl.trim(),
        event_types: hookEvents,
      });
      toast.success(`Added webhook ${hookName.trim()}`);
      setHookName("");
      setHookUrl("");
      setHookEvents([]);
      resource.retry();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to add webhook");
      setMutationError(err instanceof ApiError ? err.message : "Failed to add webhook");
    } finally {
      setBusy(null);
    }
  }

  async function testRecipient(id: number) {
    setBusy(`recipient-test-${id}`);
    try {
      await api.notifications.testRecipient(id);
      toast.success("Test email sent");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Test failed");
    } finally {
      setBusy(null);
    }
  }

  async function removeRecipient(id: number) {
    setBusy(`recipient-remove-${id}`);
    setMutationError(null);
    try {
      await api.notifications.removeRecipient(id);
      toast.success("Removed");
      resource.retry();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Remove failed";
      toast.error(message);
      setMutationError(message);
    } finally {
      setBusy(null);
    }
  }

  async function testWebhook(id: number) {
    setBusy(`webhook-test-${id}`);
    try {
      await api.notifications.testWebhook(id);
      toast.success("Test card sent");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Test failed");
    } finally {
      setBusy(null);
    }
  }

  async function removeWebhook(id: number) {
    setBusy(`webhook-remove-${id}`);
    setMutationError(null);
    try {
      await api.notifications.removeWebhook(id);
      toast.success("Removed");
      resource.retry();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Remove failed";
      toast.error(message);
      setMutationError(message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Notifications</CardTitle>
        <CardDescription>
          Route alerts to email recipients and Microsoft Teams webhooks. Leave the
          event list empty to receive all events. Webhook URLs are stored encrypted
          and never shown again (manage_alerts).
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {mutationError && <p role="alert" className="text-sm text-destructive">{mutationError}</p>}
        <DataState state={resource.state} retry={resource.retry} loadingLabel="Loading notification routes…">
        {({ eventTypes, recipients, webhooks }) => <>
        {/* Email recipients */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold">Email recipients</h3>
          {recipients.length === 0 && (
            <p className="text-xs text-muted-foreground">No recipients yet.</p>
          )}
          {recipients.map((r) => (
            <div key={r.id} className="flex items-center justify-between gap-2 text-sm">
              <span>
                {r.email}{" "}
                <span className="text-xs text-muted-foreground">· {eventSummary(r.event_types)}</span>
              </span>
              {canManage && <span className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy !== null}
                  loading={busy === `recipient-test-${r.id}`}
                  loadingLabel="Sending test email…"
                  onClick={() => void testRecipient(r.id)}
                >
                  Test
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-destructive hover:text-destructive"
                  aria-label={`Remove email recipient ${r.email}`}
                  disabled={busy !== null}
                  loading={busy === `recipient-remove-${r.id}`}
                  loadingLabel="Removing recipient…"
                  onClick={() => void removeRecipient(r.id)}
                >
                  Remove
                </Button>
              </span>}
            </div>
          ))}
          {canManage && <div className="space-y-2 rounded-md border border-input p-3">
            <label htmlFor="notification-email" className="text-sm font-medium">Recipient email</label>
            <input
              id="notification-email"
              className={inputClass}
              type="email"
              placeholder="alerts@example.com"
              value={email}
              disabled={busy === "recipient-add"}
              onChange={(e) => setEmail(e.target.value)}
            />
            <EventPicker
              all={eventTypes}
              selected={emailEvents}
              disabled={busy === "recipient-add"}
              onToggle={(e) => toggle(emailEvents, setEmailEvents, e)}
            />
            <Button size="sm" disabled={busy !== null} loading={busy === "recipient-add"} loadingLabel="Adding recipient…" onClick={addRecipient}>
              Add recipient
            </Button>
          </div>}
        </div>

        {/* Teams webhooks */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold">Microsoft Teams webhooks</h3>
          {webhooks.length === 0 && (
            <p className="text-xs text-muted-foreground">No webhooks yet.</p>
          )}
          {webhooks.map((w) => (
            <div key={w.id} className="flex items-center justify-between gap-2 text-sm">
              <span>
                {w.name}{" "}
                <span className="text-xs text-muted-foreground">· {eventSummary(w.event_types)}</span>
                {!w.enabled && <span className="text-xs text-destructive"> · disabled</span>}
              </span>
              {canManage && <span className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy !== null}
                  loading={busy === `webhook-test-${w.id}`}
                  loadingLabel="Sending test card…"
                  onClick={() => void testWebhook(w.id)}
                >
                  Test
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-destructive hover:text-destructive"
                  aria-label={`Remove webhook ${w.name}`}
                  disabled={busy !== null}
                  loading={busy === `webhook-remove-${w.id}`}
                  loadingLabel="Removing webhook…"
                  onClick={() => void removeWebhook(w.id)}
                >
                  Remove
                </Button>
              </span>}
            </div>
          ))}
          {canManage && <div className="space-y-2 rounded-md border border-input p-3">
            <label htmlFor="notification-hook-name" className="text-sm font-medium">Webhook name</label>
            <input
              id="notification-hook-name"
              className={inputClass}
              placeholder="Name (e.g. NOC channel)"
              value={hookName}
              disabled={busy === "webhook-add"}
              onChange={(e) => setHookName(e.target.value)}
            />
            <label htmlFor="notification-hook-url" className="text-sm font-medium">HTTPS webhook URL</label>
            <input
              id="notification-hook-url"
              className={inputClass}
              placeholder="https://outlook.office.com/webhook/…"
              value={hookUrl}
              disabled={busy === "webhook-add"}
              onChange={(e) => setHookUrl(e.target.value)}
            />
            <EventPicker
              all={eventTypes}
              selected={hookEvents}
              disabled={busy === "webhook-add"}
              onToggle={(e) => toggle(hookEvents, setHookEvents, e)}
            />
            <Button size="sm" disabled={busy !== null} loading={busy === "webhook-add"} loadingLabel="Adding webhook…" onClick={addWebhook}>
              Add webhook
            </Button>
          </div>}
        </div>
        </>}
        </DataState>
      </CardContent>
    </Card>
  );
}
