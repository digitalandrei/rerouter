/**
 * Authenticated in-app operator handbook.
 *
 * Keep safety and runtime claims aligned with docs/doctrine.md and the focused
 * documents under docs/ whenever controller behavior changes. This page is
 * deliberately task-oriented; the repository documents remain the engineering
 * specification and deployment reference.
 */
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  BookOpen,
  CircleCheck,
  Info,
  Search,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

type Topic = {
  id: string;
  title: string;
  group: "Start here" | "Operate" | "Respond" | "Reference";
  summary: string;
  keywords: string;
};

const topics: Topic[] = [
  {
    id: "overview",
    title: "What Rerouter does",
    group: "Start here",
    summary: "Purpose, control loop, and the most important mental model.",
    keywords: "purpose overview ddos traffic control plane detect decide execute verify",
  },
  {
    id: "safety",
    title: "Safety model",
    group: "Start here",
    summary: "Observe mode, enforce mode, automation, locks, and fail-closed behavior.",
    keywords: "observe enforce automatic manual lock cooldown verification preview token safety",
  },
  {
    id: "access",
    title: "Sign-in, 2FA, and roles",
    group: "Start here",
    summary: "Account enrollment, recovery codes, sessions, roles, and permissions.",
    keywords: "login password totp two factor recovery user roles superadmin admin operator viewer auditor",
  },
  {
    id: "model",
    title: "Core concepts",
    group: "Start here",
    summary: "How devices, interfaces, telemetry, rules, actions, and alerts relate.",
    keywords: "domain model device interface sample rule action template reroute mitigation alert",
  },
  {
    id: "setup",
    title: "First-time setup",
    group: "Start here",
    summary: "A safe commissioning sequence from first login through observe-mode validation.",
    keywords: "onboarding commissioning setup enroll discover configure notification rule test",
  },
  {
    id: "dashboard",
    title: "Dashboard",
    group: "Operate",
    summary: "System posture, health counters, active detections, and recent alerts.",
    keywords: "dashboard status counts active matches stale recent alerts banner",
  },
  {
    id: "devices",
    title: "Devices and interfaces",
    group: "Operate",
    summary: "Enrollment, SNMP discovery, SSH access, routing inventory, and protected interfaces.",
    keywords: "router device cisco ios snmp ssh key password parser view bgp peer prefix interface protected",
  },
  {
    id: "telemetry",
    title: "SNMP telemetry",
    group: "Operate",
    summary: "Polling, rate derivation, sample validity, staleness, metrics, and charts.",
    keywords: "snmp polling counters octets packets bps pps utilization errors discards optics stale valid",
  },
  {
    id: "flows",
    title: "Flow telemetry",
    group: "Operate",
    summary: "NetFlow v9 and sFlow v5 collection, sampling confidence, search, and corroboration.",
    keywords: "netflow sflow exporter sampling talkers ports asn five tuple buckets confidence corroboration",
  },
  {
    id: "rules",
    title: "Detection rules",
    group: "Operate",
    summary: "Metrics, persistence, aggregation, state transitions, recovery, and action attachment.",
    keywords: "rules threshold operator matching firing clear duration consecutive samples aggregate sum recovery",
  },
  {
    id: "templates",
    title: "Action templates",
    group: "Operate",
    summary: "The allowlisted mitigation catalog, parameters, verification, and rollback pairs.",
    keywords: "templates null route blackhole rtbh bgp advertise route map interface shutdown mss rollback",
  },
  {
    id: "mitigations",
    title: "Running mitigations",
    group: "Operate",
    summary: "Manual execution, supervised rule apply, automatic actions, history, and rollback.",
    keywords: "mitigation reroute manual apply automatic preview execute history rollback dry run commands",
  },
  {
    id: "gates",
    title: "Execution gates",
    group: "Operate",
    summary: "Every check that must pass before traffic-changing commands can run.",
    keywords: "gates operating mode inventory containment host key reachability stability locks cooldown rate limit",
  },
  {
    id: "alerts",
    title: "Alerts and notifications",
    group: "Operate",
    summary: "Alert events, email and Teams routing, retries, de-duplication, and testing.",
    keywords: "alerts email smtp teams webhook recipient subscription delivery retry deduplicate severity",
  },
  {
    id: "settings",
    title: "Settings and arming",
    group: "Operate",
    summary: "Operating mode, automatic-action master switch, global lock, and RTBH catalog.",
    keywords: "settings observe enforce arm disarm step up password totp automation global maintenance lock rtbh",
  },
  {
    id: "incidents",
    title: "Incidents and recovery",
    group: "Respond",
    summary: "Stale telemetry, blocked actions, uncertain state, rollback, and service failures.",
    keywords: "incident troubleshoot uncertain crash restart acknowledge failure blocked stale rollback database api",
  },
  {
    id: "audit",
    title: "Audit and forensics",
    group: "Respond",
    summary: "What is recorded and how to reconstruct a detection or mitigation decision.",
    keywords: "audit forensics actor ip details outputs verification commands timeline",
  },
  {
    id: "architecture",
    title: "How the system is built",
    group: "Reference",
    summary: "Browser, controller, database, network devices, trust boundaries, and data ownership.",
    keywords: "architecture react rust axum mariadb nginx cloudflare api database scheduler controller",
  },
  {
    id: "limits",
    title: "Current limits",
    group: "Reference",
    summary: "Important non-features and boundaries operators must not infer past.",
    keywords: "limitations future not implemented cloudflare ipfix bgp feed snmp v3 baseline high availability",
  },
  {
    id: "glossary",
    title: "Glossary",
    group: "Reference",
    summary: "Plain-language definitions of terms used throughout the app.",
    keywords: "glossary definitions terminology rtbh null0 corroboration stale uncertain cooldown",
  },
];

function Code({ children }: { children: ReactNode }) {
  return (
    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.9em] text-foreground">
      {children}
    </code>
  );
}

function AppLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link className="font-medium text-primary underline-offset-4 hover:underline" to={to}>
      {children}
    </Link>
  );
}

function Callout({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "safe" | "warning";
  title: string;
  children: ReactNode;
}) {
  const Icon = tone === "safe" ? ShieldCheck : tone === "warning" ? TriangleAlert : Info;
  return (
    <div
      className={cn(
        "rounded-lg border p-4",
        tone === "safe" && "border-emerald-500/30 bg-emerald-500/5",
        tone === "warning" && "border-amber-500/35 bg-amber-500/5",
        tone === "info" && "border-primary/25 bg-primary/5",
      )}
    >
      <div className="flex gap-3">
        <Icon
          className={cn(
            "mt-0.5 size-5 shrink-0",
            tone === "safe" && "text-emerald-600 dark:text-emerald-400",
            tone === "warning" && "text-amber-600 dark:text-amber-400",
            tone === "info" && "text-primary",
          )}
        />
        <div className="space-y-1.5 text-sm">
          <p className="font-semibold">{title}</p>
          <div className="leading-6 text-muted-foreground">{children}</div>
        </div>
      </div>
    </div>
  );
}

function DocSection({
  id,
  title,
  summary,
  children,
}: {
  id: string;
  title: string;
  summary: string;
  children: ReactNode;
}) {
  return (
    <Card id={id} className="scroll-mt-28">
      <CardHeader className="border-b">
        <CardTitle className="text-xl">{title}</CardTitle>
        <p className="text-sm leading-6 text-muted-foreground">{summary}</p>
      </CardHeader>
      <CardContent className="space-y-5 pt-6 text-sm leading-6">
        {children}
        <div className="border-t pt-3 text-right">
          <a className="text-xs text-muted-foreground hover:text-foreground" href="#top">
            Back to top ↑
          </a>
        </div>
      </CardContent>
    </Card>
  );
}

function H3({ children }: { children: ReactNode }) {
  return <h3 className="pt-1 text-base font-semibold tracking-tight">{children}</h3>;
}

function Steps({ children }: { children: ReactNode }) {
  return <ol className="ml-5 list-decimal space-y-2 marker:font-semibold">{children}</ol>;
}

function Bullets({ children }: { children: ReactNode }) {
  return <ul className="ml-5 list-disc space-y-1.5">{children}</ul>;
}

function CheckList({ children }: { children: ReactNode }) {
  return <ul className="space-y-2">{children}</ul>;
}

function Check({ children }: { children: ReactNode }) {
  return (
    <li className="flex gap-2">
      <CircleCheck className="mt-1 size-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
      <span>{children}</span>
    </li>
  );
}

function TopicTable({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full min-w-[620px] text-left text-sm">{children}</table>
    </div>
  );
}

const thClass = "border-b bg-muted/50 px-3 py-2 font-semibold";
const tdClass = "border-b px-3 py-2.5 align-top";

export default function Documentation() {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const visibleTopics = useMemo(
    () =>
      normalizedQuery
        ? topics.filter((topic) =>
            `${topic.title} ${topic.summary} ${topic.keywords}`
              .toLowerCase()
              .includes(normalizedQuery),
          )
        : topics,
    [normalizedQuery],
  );
  const visibleIds = new Set(visibleTopics.map((topic) => topic.id));
  const show = (id: string) => visibleIds.has(id);
  const groups: Topic["group"][] = ["Start here", "Operate", "Respond", "Reference"];

  return (
    <div id="top" className="mx-auto max-w-7xl space-y-6">
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <BookOpen className="size-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Rerouter documentation</h1>
            <p className="text-sm text-muted-foreground">
              Operator and administrator handbook · behavior described as shipped
            </p>
          </div>
        </div>
        <p className="max-w-4xl text-sm leading-6 text-muted-foreground">
          This guide explains the whole application—from telemetry entering the controller to a
          verified mitigation—and gives safe procedures for normal operation and incidents. Use
          the page links to move directly into the relevant workflow.
        </p>
      </div>

      <div className="relative max-w-2xl">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search topics: uncertain, flow sampling, rollback, roles…"
          aria-label="Search documentation topics"
          className="pl-9 pr-20"
        />
        {query && (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="absolute right-1 top-1/2 h-7 -translate-y-1/2"
            onClick={() => setQuery("")}
          >
            Clear
          </Button>
        )}
      </div>

      <div className="grid items-start gap-6 lg:grid-cols-[240px_minmax(0,1fr)]">
        <aside className="rounded-lg border bg-card p-3 lg:sticky lg:top-28">
          <p className="px-2 pb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            On this page
          </p>
          {visibleTopics.length === 0 ? (
            <p className="px-2 py-3 text-sm text-muted-foreground">No matching topic.</p>
          ) : (
            <nav aria-label="Documentation table of contents" className="space-y-3">
              {groups.map((group) => {
                const items = visibleTopics.filter((topic) => topic.group === group);
                if (items.length === 0) return null;
                return (
                  <div key={group}>
                    <p className="px-2 py-1 text-xs font-medium text-muted-foreground">{group}</p>
                    <ul>
                      {items.map((topic) => (
                        <li key={topic.id}>
                          <a
                            href={`#${topic.id}`}
                            className="block rounded-md px-2 py-1.5 text-sm hover:bg-muted"
                          >
                            {topic.title}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })}
            </nav>
          )}
        </aside>

        <div className="min-w-0 space-y-6">
          {visibleTopics.length === 0 && (
            <Card>
              <CardContent className="py-10 text-center">
                <p className="font-medium">No documentation topic matched “{query}”.</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  Try a page name, domain term, status, or action such as “rules”, “stale”, or
                  “blackhole”.
                </p>
              </CardContent>
            </Card>
          )}

          {show("overview") && (
            <DocSection
              id="overview"
              title="What Rerouter does"
              summary="Rerouter is a safety-critical control plane for detecting abnormal traffic and applying bounded Cisco IOS mitigations."
            >
              <p>
                Rerouter watches enrolled router interfaces, evaluates stateful threshold rules,
                alerts operators, and—only when explicitly armed—can change routing over SSH. It
                is designed to prefer no action over an action based on stale, ambiguous, or
                unverified state.
              </p>
              <div className="grid gap-2 md:grid-cols-5">
                {[
                  ["1", "Collect", "Poll SNMP and optionally receive flows"],
                  ["2", "Normalize", "Derive rates and reject invalid samples"],
                  ["3", "Detect", "Advance rules through matching and firing"],
                  ["4", "Act", "Render or execute allowlisted templates"],
                  ["5", "Verify", "Read the router state back and persist evidence"],
                ].map(([number, title, body]) => (
                  <div key={number} className="rounded-lg border bg-muted/20 p-3">
                    <Badge variant="outline" className="mb-2">
                      {number}
                    </Badge>
                    <p className="font-semibold">{title}</p>
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">{body}</p>
                  </div>
                ))}
              </div>
              <Callout tone="safe" title="The default is observation, not execution">
                Rerouter ships in <strong>observe</strong> mode. Collection and detection work,
                but no manual or automatic mitigation runs. Fired-rule alerts include the exact
                plan that would have run, letting you validate the system against live traffic
                without changing routing.
              </Callout>
              <H3>What it controls</H3>
              <Bullets>
                <li>Local IPv4/IPv6 Null0 routes and tagged Null0 routes used for upstream RTBH.</li>
                <li>BGP neighbor administrative state and bounded outbound advertisement changes.</li>
                <li>Selected route-map assignments and interface MSS settings.</li>
                <li>Interface shutdown/no-shutdown, always manual-only and blocked on protected paths.</li>
              </Bullets>
              <p>
                It does not provide arbitrary CLI execution. Every action originates from a typed,
                allowlisted template and is checked again immediately before use.
              </p>
            </DocSection>
          )}

          {show("safety") && (
            <DocSection
              id="safety"
              title="Safety model"
              summary="Several independent controls must agree before the controller is allowed to move traffic."
            >
              <TopicTable>
                <thead>
                  <tr>
                    <th className={thClass}>Control</th>
                    <th className={thClass}>What it means</th>
                    <th className={thClass}>Default</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className={tdClass}>Operating mode</td>
                    <td className={tdClass}>
                      <Code>observe</Code> renders plans only; <Code>enforce</Code> permits execution
                      if every remaining gate passes.
                    </td>
                    <td className={tdClass}>Observe</td>
                  </tr>
                  <tr>
                    <td className={tdClass}>Automatic master switch</td>
                    <td className={tdClass}>
                      Global permission for rule-driven execution. It does not enable any individual rule.
                    </td>
                    <td className={tdClass}>Off</td>
                  </tr>
                  <tr>
                    <td className={tdClass}>Per-rule automation</td>
                    <td className={tdClass}>
                      Opts one rule into hands-off execution; each attached template must also allow automation.
                    </td>
                    <td className={tdClass}>Off</td>
                  </tr>
                  <tr>
                    <td className={tdClass}>Global maintenance lock</td>
                    <td className={tdClass}>Blocks every new mitigation while maintenance or investigation is in progress.</td>
                    <td className={tdClass}>Unlocked</td>
                  </tr>
                  <tr>
                    <td className={tdClass}>Device lock</td>
                    <td className={tdClass}>Blocks one router after uncertainty or by deliberate operator action.</td>
                    <td className={tdClass}>No lock</td>
                  </tr>
                </tbody>
              </TopicTable>
              <H3>Manual, supervised, and automatic are distinct</H3>
              <Bullets>
                <li>
                  <strong>Manual mitigation:</strong> an authorized operator chooses a template,
                  device, and parameters, reviews the server-rendered commands, then executes.
                </li>
                <li>
                  <strong>Supervised rule apply:</strong> an operator applies a firing rule's
                  already-configured action set. The rule must explicitly allow manual apply.
                </li>
                <li>
                  <strong>Automatic mitigation:</strong> a firing edge launches enabled actions
                  without an operator. Enforce mode, both automation switches, template policy,
                  and every device gate must all pass.
                </li>
              </Bullets>
              <Callout tone="warning" title="A UI button is never the authorization boundary">
                The controller rechecks identity, permissions, mode, plan binding, fresh inventory,
                locks, reachability, cooldowns, target containment, and verification. Hiding a
                control in the browser is only a usability feature.
              </Callout>
              <H3>Exact-preview binding</H3>
              <p>
                In enforce mode, manual execution, supervised rule apply, and rollback start with a
                server-rendered dry run. The server returns a five-minute, single-use token bound to
                the user, action scope, reason, targets, parameters, and exact plan. A changed or
                replayed request is refused. Observe-mode previews do not grant execution.
              </p>
              <H3>Success means verified state</H3>
              <p>
                Sending a command is not success. The controller persists the transition, opens a
                separate read-only SSH session, runs the template's show command, and checks the
                expected and rejected text. An ambiguous transport result becomes
                <Code>uncertain</Code>, which locks the device for human review.
              </p>
            </DocSection>
          )}

          {show("access") && (
            <DocSection
              id="access"
              title="Sign-in, 2FA, and roles"
              summary="Every account uses password plus TOTP; authorization is enforced by server-side permissions on every request."
            >
              <H3>Normal sign-in</H3>
              <Steps>
                <li>Enter email and password. A correct password creates only a short pre-2FA session.</li>
                <li>Enter a current six-digit authenticator code or one unused recovery code.</li>
                <li>The controller promotes the session and the app loads your roles and permissions.</li>
              </Steps>
              <p>
                The browser receives an HttpOnly session cookie, not an API token visible to
                JavaScript. Normal sessions last up to 12 hours, or 7 days with “Remember me,” and
                expire after 60 minutes of inactivity by default.
              </p>
              <H3>First login or a 2FA reset</H3>
              <Steps>
                <li>Obtain the separate one-time enrollment code from the superadmin out of band.</li>
                <li>Enter it with your password. Scan the displayed authenticator material.</li>
                <li>Enter a live code to bind the authenticator.</li>
                <li>Save the eight recovery codes shown once, then acknowledge them to enter the app.</li>
              </Steps>
              <Callout tone="warning" title="Recovery codes are single-use secrets">
                Store them outside the app. They are held in the database only as password-style
                hashes and cannot be displayed again. A superadmin can reset 2FA, which revokes
                existing sessions and creates a new enrollment code.
              </Callout>
              <H3>Role guide</H3>
              <TopicTable>
                <thead>
                  <tr>
                    <th className={thClass}>Role</th>
                    <th className={thClass}>Intended use</th>
                    <th className={thClass}>Key boundaries</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ["Superadmin", "Platform owner", "Everything, including users and device enrollment"],
                    ["Admin", "Safety and control-plane administrator", "Rules, locks, alerts, mode changes, and manual actions; no users or device enrollment"],
                    ["Operator", "Incident operator", "View operations, edit rules, run manual actions, and acknowledge uncertain actions"],
                    ["Viewer", "Read-only operations", "Dashboards and operational data; no changes"],
                    ["Auditor", "Forensic/configuration review", "Audit and configuration visibility; no operational changes"],
                  ].map(([role, use, boundary]) => (
                    <tr key={role}>
                      <td className={tdClass}><strong>{role}</strong></td>
                      <td className={tdClass}>{use}</td>
                      <td className={tdClass}>{boundary}</td>
                    </tr>
                  ))}
                </tbody>
              </TopicTable>
              <p>
                The <AppLink to="/users">Users page</AppLink> is visible only with
                <Code>manage_users</Code>. Page visibility does not replace backend permission
                checks.
              </p>
            </DocSection>
          )}

          {show("model") && (
            <DocSection
              id="model"
              title="Core concepts"
              summary="Understanding these relationships makes every page and alert easier to read."
            >
              <div className="rounded-lg border bg-muted/20 p-4 font-mono text-xs leading-6 md:text-sm">
                Device → Interfaces → Telemetry samples → Detection rule state
                <br />
                Detection rule → Ordered action templates → Target devices
                <br />
                Fired rule → Alert + optional mitigation → Verification → Audit trail
              </div>
              <TopicTable>
                <thead><tr><th className={thClass}>Concept</th><th className={thClass}>Meaning</th></tr></thead>
                <tbody>
                  {[
                    ["Device", "An enrolled Cisco IOS router reached read-only by SNMP and, when configured, operationally by SSH."],
                    ["Interface", "A discovered router interface. Every discovered interface is polled and can be selected by a rule."],
                    ["Telemetry sample", "A timestamped observation. Valid SNMP rates require two consecutive counter reads."],
                    ["Detection rule", "A stateful condition on one interface, a sum of interfaces, or a selected flow bucket."],
                    ["Rule action", "One ordered template + target router + validated parameter set attached to a rule."],
                    ["Action template", "An allowlisted command plan, verification check, and optional rollback pairing."],
                    ["Mitigation / reroute", "One persisted execution attempt against one device, with a state machine and evidence."],
                    ["Alert", "A durable event generated by detection, execution, arming, security, or degradation."],
                    ["Lock / cooldown", "A hard block or time-based throttle that prevents unsafe action scheduling."],
                  ].map(([term, meaning]) => (
                    <tr key={term}><td className={tdClass}><strong>{term}</strong></td><td className={tdClass}>{meaning}</td></tr>
                  ))}
                </tbody>
              </TopicTable>
              <p>
                A rule does not own one implicit command. Its actions are explicit rows, so one
                detection can fan out to several routers or apply several ordered changes. Each
                device execution is gated and recorded independently.
              </p>
            </DocSection>
          )}

          {show("setup") && (
            <DocSection
              id="setup"
              title="First-time setup"
              summary="Commission the system in observe mode and build confidence before considering enforce mode."
            >
              <Steps>
                <li>
                  <strong>Complete account enrollment.</strong> Bind TOTP and save recovery codes.
                </li>
                <li>
                  <strong>Confirm the safety posture.</strong> On <AppLink to="/settings">Settings</AppLink>,
                  verify mode is Observe, automatic reroutes are off, and no unexpected lock exists.
                </li>
                <li>
                  <strong>Configure notifications.</strong> Add verified email recipients and/or a
                  Teams webhook, select event subscriptions, and send tests.
                </li>
                <li>
                  <strong>Enroll a router.</strong> Add its SNMP v2c management endpoint and polling
                  interval on <AppLink to="/devices">Devices</AppLink>. Add SSH credentials if this
                  router will ever execute mitigations.
                </li>
                <li>
                  <strong>Test SNMP, then discover interfaces.</strong> The first poll establishes
                  counter baselines; the next valid poll produces rates.
                </li>
                <li>
                  <strong>Commission SSH safely.</strong> Install the generated public key or supplied
                  account, pin the first host key, run the command-access check, and discover BGP
                  peers, announced prefixes, prefix lists, and route maps.
                </li>
                <li>
                  <strong>Protect critical paths.</strong> Mark management/transit interfaces as
                  protected so shutdown and MSS-add actions cannot target them.
                </li>
                <li>
                  <strong>Create alert-only rules.</strong> Start with realistic thresholds and
                  persistence. Leave manual apply and automatic action toggles off until evidence is
                  understood.
                </li>
                <li>
                  <strong>Attach and preview actions.</strong> Inspect exact would-run commands and
                  rollback commands in observe mode. Confirm prefixes, peer selection, local ASN,
                  tags, and target devices.
                </li>
                <li>
                  <strong>Soak and review.</strong> Let real traffic exercise rules. Review matching,
                  firing, clearing, stale periods, alerts, and false positives. Arming is a separate,
                  deliberate decision requiring fresh password and TOTP.
                </li>
              </Steps>
              <Callout tone="safe" title="Recommended commissioning outcome">
                The system can collect, detect, alert, render every planned action, and demonstrate
                correct recovery behavior while still unable to change a router. That is a complete
                and useful observe-mode deployment.
              </Callout>
            </DocSection>
          )}

          {show("dashboard") && (
            <DocSection
              id="dashboard"
              title="Dashboard"
              summary="The dashboard answers: Is the controller healthy, is telemetry trustworthy, and does anything need attention now?"
            >
              <Bullets>
                <li><strong>Devices reachable:</strong> SNMP reachability, not proof that SSH execution is usable.</li>
                <li><strong>Interfaces monitored:</strong> discovered interfaces currently represented by the controller.</li>
                <li><strong>Active rule matches:</strong> rules in a firing state; the same count appears on the Mitigations sidebar badge.</li>
                <li><strong>Alerts (24 h):</strong> recent durable alert events, not only delivered messages.</li>
                <li><strong>Telemetry stale:</strong> enabled devices that have never polled or exceeded the configured freshness window.</li>
              </Bullets>
              <p>
                The persistent banner states Observe mode. Treat it as the authoritative reminder
                that execution is blocked. Active detections link to the mitigation workflow, while
                recent alerts link to the event view. Refresh the source page before making an
                incident decision; summary counters are orientation, not execution evidence.
              </p>
              <Callout tone="warning" title="Reachable is not the same as mitigation-ready">
                SNMP may be healthy while SSH is unavailable, underprivileged, still stabilizing,
                locked, or missing fresh routing inventory. Check the device's Reachability and
                Settings tabs before expecting an action to run.
              </Callout>
            </DocSection>
          )}

          {show("devices") && (
            <DocSection
              id="devices"
              title="Devices and interfaces"
              summary="Devices provide telemetry, routing context, and the SSH boundary through which templates execute."
            >
              <H3>Enrollment fields</H3>
              <Bullets>
                <li>Name and management hostname/IP.</li>
                <li>SNMP v2c port, read-only community, and poll interval.</li>
                <li>Optional SSH username, port, and either password or private-key authentication.</li>
                <li>An in-app-generated RSA keypair can be used; only the public key is shown, while the private key is encrypted at rest.</li>
              </Bullets>
              <p>
                SNMP communities, SSH passwords, private keys, and passphrases are encrypted by the
                controller and never returned by the API. Editing uses presence indicators, not the
                stored secret value.
              </p>
              <H3>Recommended device workflow</H3>
              <Steps>
                <li>Run the SNMP test to read identity and reachability.</li>
                <li>Discover interfaces. Inventory refresh also runs at startup and daily.</li>
                <li>Open the device. Review Overview, Interfaces, Flows, and—if authorized—Settings.</li>
                <li>Test SSH. First contact pins the device host key; a later mismatch fails closed.</li>
                <li>Run Command access. A usable account must reach privileged EXEC and pass every read/no-op capability check.</li>
                <li>Discover BGP peers over SNMP and routing context over SSH.</li>
                <li>Mark management, transit, and other critical interfaces protected.</li>
              </Steps>
              <H3>SSH status</H3>
              <TopicTable>
                <thead><tr><th className={thClass}>Status</th><th className={thClass}>Interpretation</th></tr></thead>
                <tbody>
                  <tr><td className={tdClass}><Code>reachable</Code></td><td className={tdClass}>Privileged access works and all required capability checks pass.</td></tr>
                  <tr><td className={tdClass}><Code>no_privilege</Code></td><td className={tdClass}>Login works, but privilege 15 or one or more required parser-view commands are denied.</td></tr>
                  <tr><td className={tdClass}><Code>unreachable</Code></td><td className={tdClass}>Connection or authentication failed.</td></tr>
                  <tr><td className={tdClass}><Code>unknown</Code></td><td className={tdClass}>No probe result exists yet.</td></tr>
                </tbody>
              </TopicTable>
              <p>
                Automatic mitigations also require continuous SSH reachability for about one minute.
                The stability timer resets after an unhealthy probe and on controller startup. Manual
                and rollback actions may proceed during stabilization, but still need live reachability.
              </p>
              <H3>Routing inventory and why freshness matters</H3>
              <Bullets>
                <li>BGP peers provide neighbor address, ASNs, state, labels, and route-map context.</li>
                <li>Announced prefixes bound Null0/RTBH targets to address space the router recently advertised.</li>
                <li>Outbound prefix-list discovery supplies safe choices for advertisement templates.</li>
                <li>Fresh interface and BGP inventory is required for new actions; stale picker values are revalidated server-side.</li>
              </Bullets>
              <H3>Protected interfaces</H3>
              <p>
                Mark an interface protected when changing it could remove management, transit, or SSH
                access. Shutdown and MSS-add actions are blocked. Corrective inverse actions—no
                shutdown and MSS removal—remain possible so an existing condition can be repaired.
              </p>
              <p>Start at <AppLink to="/devices">Devices</AppLink>.</p>
            </DocSection>
          )}

          {show("telemetry") && (
            <DocSection
              id="telemetry"
              title="SNMP telemetry"
              summary="SNMP v2c polling is the primary volume signal and the corroborating source for flow-driven automatic actions."
            >
              <H3>How rates are calculated</H3>
              <div className="rounded-lg border bg-muted/30 p-3 font-mono text-xs">
                rx_bps = (current_octets − previous_octets) × 8 ÷ elapsed_seconds
                <br />
                rx_pps = (current_packets − previous_packets) ÷ elapsed_seconds
                <br />
                utilization = bits_per_second ÷ interface_speed × 100
              </div>
              <p>
                The controller prefers 64-bit high-capacity counters. Raw counters remain the next
                baseline; derived rates are stored separately as the current sample and in retained
                history.
              </p>
              <H3>Sample validity</H3>
              <Bullets>
                <li>The first poll has no prior counter and is invalid for rate-based detection.</li>
                <li>A counter moving backward indicates wrap/reset/reboot; that sample is invalid, but it becomes the next baseline.</li>
                <li>A device transport failure marks telemetry unreachable and lets old samples become stale.</li>
                <li>Detection advances only from fresh samples whose <Code>valid_sample</Code> flag is true.</li>
              </Bullets>
              <H3>Metrics</H3>
              <TopicTable>
                <thead><tr><th className={thClass}>Metric</th><th className={thClass}>Use</th></tr></thead>
                <tbody>
                  <tr><td className={tdClass}>Rx/Tx bps</td><td className={tdClass}>Inbound/outbound bandwidth rate.</td></tr>
                  <tr><td className={tdClass}>Rx/Tx pps</td><td className={tdClass}>Inbound/outbound packet rate.</td></tr>
                  <tr><td className={tdClass}>Rx/Tx utilization %</td><td className={tdClass}>Rate relative to discovered interface speed.</td></tr>
                  <tr><td className={tdClass}>In/Out error rate</td><td className={tdClass}>Counter delta per second, useful for fault and error-storm rules.</td></tr>
                  <tr><td className={tdClass}>Status and discards</td><td className={tdClass}>Operational context and charts; status rules can detect a down link through the API model.</td></tr>
                  <tr><td className={tdClass}>Optics</td><td className={tdClass}>Temperature and optical power when the device exposes pluggable data.</td></tr>
                </tbody>
              </TopicTable>
              <H3>Interface page</H3>
              <p>
                The interface detail page combines identity, current counters/status, attached rules,
                and retained charts for traffic, packets, errors, discards, and optics. Chart smoothing
                changes presentation only; it does not alter stored samples or rule evaluation.
              </p>
              <Callout tone="warning" title="Never reason from an old value as if it were current">
                Stale and invalid samples are deliberately excluded from detection. If a chart has
                stopped moving or the dashboard reports stale telemetry, repair collection before
                changing thresholds or expecting automatic action.
              </Callout>
            </DocSection>
          )}

          {show("flows") && (
            <DocSection
              id="flows"
              title="Flow telemetry"
              summary="The optional passive collector adds traffic composition while preserving stricter confidence gates for automation."
            >
              <p>
                The controller can receive NetFlow v9 and sFlow v5 on separate UDP ports. Collection
                is off by default and binds an explicitly configured management address when enabled.
                Only datagrams whose source resolves to an enrolled device are accepted by the shipped
                policy.
              </p>
              <H3>What flow data adds</H3>
              <Bullets>
                <li>Top five-tuples, destination/source ports, source/destination ASNs, and interfaces.</li>
                <li>Ingress/egress direction and protocol-aware investigation.</li>
                <li><Code>flow_bps</Code> and <Code>flow_pps</Code> rule metrics with direction and optional port/protocol selectors.</li>
                <li>Flow auto-target: resolve the heaviest attacked destination host at mitigation time.</li>
              </Bullets>
              <H3>Sampling and confidence</H3>
              <p>
                Flow exports may describe only one in N packets. The app retains raw counts and
                sampling-scaled estimates, identifies the effective sampling source, and labels
                confidence. Unknown, missing, or suspicious sampling is visible as low confidence.
              </p>
              <TopicTable>
                <thead><tr><th className={thClass}>Signal</th><th className={thClass}>Effect</th></tr></thead>
                <tbody>
                  <tr><td className={tdClass}>Enrolled exporter identity</td><td className={tdClass}>Unrecognized UDP sources are ignored when the allowlist is enabled.</td></tr>
                  <tr><td className={tdClass}>Closed, fresh bucket</td><td className={tdClass}>Rules do not evaluate incomplete or stale bucket evidence.</td></tr>
                  <tr><td className={tdClass}>Sampling confidence</td><td className={tdClass}>Low confidence blocks automatic mitigation but remains visible for investigation.</td></tr>
                  <tr><td className={tdClass}>SNMP corroboration</td><td className={tdClass}>Estimated flow volume must agree with contemporaneous same-interface SNMP inside configured bounds.</td></tr>
                  <tr><td className={tdClass}>Separate flow-auto switch</td><td className={tdClass}>Flow data cannot drive automatic traffic changes merely because collection is enabled.</td></tr>
                </tbody>
              </TopicTable>
              <H3>Using the Flows page</H3>
              <Bullets>
                <li><strong>Top statistics:</strong> rank traffic, ports, ASNs, or talkers over the selected recent window.</li>
                <li><strong>Search:</strong> locate a tuple and see which device interfaces and directions observed it.</li>
                <li><strong>Device Flows tab:</strong> scopes the same investigation to one router and shows exporter health.</li>
              </Bullets>
              <Callout tone="warning" title="UDP source allowlisting is not cryptographic identity">
                Protect collector ports with management-plane ACLs and uRPF/anti-spoofing controls.
                SNMP corroboration reduces bad automation decisions but does not authenticate a forged
                datagram source.
              </Callout>
              <p>Open <AppLink to="/flows">Flows</AppLink>.</p>
            </DocSection>
          )}

          {show("rules") && (
            <DocSection
              id="rules"
              title="Detection rules"
              summary="Rules turn trusted observations into stateful detections; firing is a signal, not permission to execute."
            >
              <H3>Rule inputs</H3>
              <Bullets>
                <li>A single interface, or a sum across selected interfaces that may span devices.</li>
                <li>A supported SNMP or flow metric and one comparison operator: <Code>&gt;</Code>, <Code>&gt;=</Code>, <Code>&lt;</Code>, <Code>&lt;=</Code>, <Code>==</Code>, or <Code>!=</Code>.</li>
                <li>A threshold in raw units: bits/sec, packets/sec, percent, or errors/sec.</li>
                <li>Persistence, severity, enabled state, and recovery behavior.</li>
                <li>Optional ordered mitigation actions and separate manual-apply/automatic switches.</li>
              </Bullets>
              <H3>Persistence and the rising edge</H3>
              <p>
                A matching observation moves a clear rule to <Code>matching</Code>. It becomes
                <Code>firing</Code> only after all configured persistence gates pass: held duration
                and consecutive valid matches. A zero disables that gate. The rule emits the fired
                event on the rising edge, not on every polling tick while it stays firing.
              </p>
              <div className="rounded-lg border bg-muted/20 p-4 text-center font-mono text-xs md:text-sm">
                clear → matching → firing → recovery → clear
              </div>
              <p>
                SNMP rules normally use consecutive samples. Flow rules use a duration window and
                reject a consecutive-sample requirement because repeated controller ticks can refer
                to the same closed flow bucket.
              </p>
              <H3>Single vs summed rules</H3>
              <p>
                Summed rules support bps, pps, and error-rate metrics. Utilization percentages and
                link status cannot be meaningfully summed. If any member lacks a fresh valid sample,
                the whole summed observation is skipped; the engine never fires from a partial group.
              </p>
              <H3>Recovery modes</H3>
              <TopicTable>
                <thead><tr><th className={thClass}>Mode</th><th className={thClass}>How firing clears</th></tr></thead>
                <tbody>
                  <tr><td className={tdClass}>Auto</td><td className={tdClass}>Condition stops matching for the configured recovery window/sample count.</td></tr>
                  <tr><td className={tdClass}>Threshold</td><td className={tdClass}>A distinct recovery threshold is crossed, providing explicit hysteresis.</td></tr>
                  <tr><td className={tdClass}>Manual</td><td className={tdClass}>An operator explicitly clears the rule; clearing executes no rollback or action.</td></tr>
                </tbody>
              </TopicTable>
              <H3>Flow selectors</H3>
              <p>
                A flow rule selects ingress or egress and may select a source/destination port plus a
                protocol. A protocol without a port is rejected because stored rollups do not contain
                a protocol-only bucket. Absence of a current matching port is treated conservatively,
                never as permission to reuse an older non-zero bucket.
              </p>
              <H3>Actions and toggles</H3>
              <Bullets>
                <li><strong>Enabled:</strong> allows detection evaluation.</li>
                <li><strong>Manual apply:</strong> lets an operator apply attached actions while the rule is currently firing.</li>
                <li><strong>Auto:</strong> opts the rule into hands-off action, still requiring every global and template gate.</li>
                <li><strong>Action enabled:</strong> includes that individual ordered action in apply/automatic execution.</li>
              </Bullets>
              <p>
                Use <AppLink to="/rules">Rules</AppLink> to create conditions, watch live state and
                progression, manage action sets, clear a firing rule, or disable evaluation.
              </p>
            </DocSection>
          )}

          {show("templates") && (
            <DocSection
              id="templates"
              title="Action templates"
              summary="Templates are the complete command vocabulary available to the mitigation engine; there is no arbitrary-command feature."
            >
              <p>
                A template defines typed parameters, exact configuration commands, a separate show
                verification, whether automatic use is permitted, and an optional inverse template.
                Values such as IPs, CIDRs, ASNs, tags, interface names, peers, route maps, and prefix
                lists are validated and often resolved from fresh inventory.
              </p>
              <TopicTable>
                <thead><tr><th className={thClass}>Family</th><th className={thClass}>Purpose</th><th className={thClass}>Rollback</th></tr></thead>
                <tbody>
                  <tr><td className={tdClass}>Local Null0</td><td className={tdClass}>Install/remove an IPv4 or IPv6 Null0 route, dropping destination traffic on that router.</td><td className={tdClass}>Withdraw/add inverse</td></tr>
                  <tr><td className={tdClass}>Tagged blackhole / RTBH</td><td className={tdClass}>Install/remove a tagged Null0 route that the router's policy redistributes with an upstream blackhole community.</td><td className={tdClass}>Withdraw/add inverse</td></tr>
                  <tr><td className={tdClass}>BGP session</td><td className={tdClass}>Administratively shut or enable one neighbor.</td><td className={tdClass}>Opposite neighbor state</td></tr>
                  <tr><td className={tdClass}>BGP advertisement</td><td className={tdClass}>Add/remove a prefix-list permit for one peer, then soft-clear outbound.</td><td className={tdClass}>Remove/add inverse</td></tr>
                  <tr><td className={tdClass}>BGP route map</td><td className={tdClass}>Set or restore a neighbor route-map assignment from discovered context.</td><td className={tdClass}>Restore the captured prior assignment</td></tr>
                  <tr><td className={tdClass}>TCP MSS</td><td className={tdClass}>Apply/remove interface TCP adjust-mss.</td><td className={tdClass}>Remove/add inverse</td></tr>
                  <tr><td className={tdClass}>Interface state</td><td className={tdClass}>Shutdown/no-shutdown an interface. Disruptive and protected-interface aware.</td><td className={tdClass}>Opposite state</td></tr>
                </tbody>
              </TopicTable>
              <Callout tone="warning" title="Local Null0 and upstream RTBH are not interchangeable">
                A local Null0 drops traffic when it reaches the selected router. A tagged blackhole
                relies on router policy and an approved RTBH tag/community so the route is propagated
                for upstream discard. Verify the router's route-map design before relying on RTBH.
              </Callout>
              <H3>Automatic policy</H3>
              <p>
                New templates are manual-only unless explicitly marked automatic-allowed. Route-map
                changes and interface shutdown/no-shutdown remain manual-only. A rule's Auto toggle
                cannot override template policy.
              </p>
              <H3>Combining actions</H3>
              <p>
                Multi-step incident policy is represented as multiple ordered rule actions—for
                example remove an advertisement from a saturated peer, advertise through another,
                then apply MSS adjustment. Each action is persisted, gated, verified, and rollbackable
                on its own target device.
              </p>
              <p>Inspect rendered plans on <AppLink to="/templates">Action templates</AppLink>.</p>
            </DocSection>
          )}

          {show("mitigations") && (
            <DocSection
              id="mitigations"
              title="Running mitigations"
              summary="Every traffic-changing workflow previews first, persists before pushing, verifies afterward, and leaves an audit trail."
            >
              <H3>Manual mitigation</H3>
              <Steps>
                <li>Open <AppLink to="/mitigations/manual">New manual mitigation</AppLink>.</li>
                <li>Select a template and router. Fill parameters using inventory-backed pickers.</li>
                <li>Optionally enter a reason; it becomes part of the audit record and preview binding.</li>
                <li>Preview exact configuration commands, verification, and rollback commands.</li>
                <li>Review live SSH posture and any warning. Changing a field invalidates the preview.</li>
                <li>Execute. Observe mode returns a would-run result; enforce mode consumes the one-use token and runs only if every gate still passes.</li>
                <li>Open History to inspect state, outputs, and verification.</li>
              </Steps>
              <H3>Supervised apply from a firing rule</H3>
              <p>
                On the Detections or Alerts tab, an operator can apply a rule's configured action set
                only while it is firing and only when Manual apply was enabled on the rule. This uses
                the manual permission and exact-preview workflow. The automatic master switch does not
                block a deliberate operator apply, but mode, locks, cooldowns, rate limits, reachability,
                and all other execution gates still apply.
              </p>
              <H3>Automatic execution</H3>
              <p>
                Automatic action is considered only on the firing edge. It requires enforce mode,
                global automatic actions on, the rule's Auto toggle on, each action enabled, each
                template automatic-allowed, and—when flow-derived—the separate flow automation and
                confidence/corroboration gates. A blocked action is recorded and included in the
                fired-rule event; detection continues.
              </p>
              <H3>State machine</H3>
              <div className="rounded-lg border bg-muted/20 p-4 text-center font-mono text-xs md:text-sm">
                planned → pending → running → verifying → succeeded
                <br />
                running/verifying → failed or uncertain
              </div>
              <Bullets>
                <li><Code>failed</Code> means the controller obtained a definite negative outcome.</li>
                <li><Code>uncertain</Code> means it cannot prove the final router state; the device is locked.</li>
                <li>Cancellation applies only where the current persisted state can still be safely canceled.</li>
              </Bullets>
              <H3>Rollback</H3>
              <p>
                A succeeded action does not expire automatically. Use its paired rollback from History
                when the mitigation should be lifted. Rollback gets its own preview, state machine,
                commands, verification, audit entry, and alert trail. It bypasses cooldown/rate
                throttles as a corrective action, but still obeys mode, locks, serialization,
                reachability, persistence, command allowlisting, and verification.
              </p>
              <H3>Mitigations page tabs</H3>
              <Bullets>
                <li><strong>Detections:</strong> currently firing rules and supervised action controls.</li>
                <li><strong>Alerts:</strong> recent detection, reroute, safety, security, and degradation events.</li>
                <li><strong>History:</strong> action attempts, detail evidence, rollback, and uncertain acknowledgement.</li>
              </Bullets>
              <p>Open <AppLink to="/mitigations">Mitigations</AppLink>.</p>
            </DocSection>
          )}

          {show("gates") && (
            <DocSection
              id="gates"
              title="Execution gates"
              summary="The executor revalidates these controls immediately before reserving and changing a device."
            >
              <CheckList>
                <Check><strong>Operating mode:</strong> must be enforce. Observe always returns a plan without execution.</Check>
                <Check><strong>Request intent:</strong> must not be dry-run, and enforce-mode operator workflows need a valid one-use preview token.</Check>
                <Check><strong>Authorization:</strong> the session and required permission must still be valid.</Check>
                <Check><strong>Global lock:</strong> no active maintenance/circuit-breaker lock.</Check>
                <Check><strong>Fresh canonical inventory:</strong> interface, peer, prefix, prefix-list, route-map, ASN, and tag values must resolve to recent device/catalog state.</Check>
                <Check><strong>Target containment:</strong> Null0/RTBH destinations must be inside recently discovered announced space; flow auto-target can only choose an owned host.</Check>
                <Check><strong>Device lock and uncertainty:</strong> no device lock and no unresolved uncertain action.</Check>
                <Check><strong>Serialization:</strong> no other action may already be running on the same router.</Check>
                <Check><strong>Protected path:</strong> disruptive interface actions cannot target protected interfaces.</Check>
                <Check><strong>Cooldowns and rate limit:</strong> device, rule, and global action throttles must permit the action (rollback has the documented corrective exception).</Check>
                <Check><strong>SSH reachability and command access:</strong> live or very recent privileged access must pass every required capability check.</Check>
                <Check><strong>Host identity:</strong> first-contact pinning must commit, and later fingerprints must match.</Check>
                <Check><strong>Automatic stability:</strong> automatic actions require about one minute of continuous SSH health after recovery/startup.</Check>
                <Check><strong>Automatic policy:</strong> global, rule, action, template, and optional flow gates must all allow it.</Check>
                <Check><strong>Persistence:</strong> the controller must be able to record state before and after each execution step.</Check>
                <Check><strong>Verification:</strong> a separate show check must prove the intended state before success is recorded.</Check>
              </CheckList>
              <H3>Default throttles</H3>
              <Bullets>
                <li>Same device: 300 seconds after an action.</li>
                <li>Same rule: 900 seconds after its actions run.</li>
                <li>Global: at most 3 executed actions in a rolling 600-second window.</li>
              </Bullets>
              <Callout tone="info" title="A blocked action is a useful result">
                The block reason identifies which precondition was unsafe. Fix or deliberately
                resolve that condition; do not weaken unrelated controls to make a button succeed.
              </Callout>
            </DocSection>
          )}

          {show("alerts") && (
            <DocSection
              id="alerts"
              title="Alerts and notifications"
              summary="Alert events are written durably first, then delivered asynchronously by email and/or Microsoft Teams."
            >
              <H3>Common event families</H3>
              <Bullets>
                <li>Rule fired, including observed value, threshold, interface, and would-run/executed action results.</li>
                <li>Mitigation started, succeeded, failed, or uncertain.</li>
                <li>Operating mode, automatic-action, and global-lock changes.</li>
                <li>Security events such as account lockout and recovery-code use.</li>
                <li>Automatic action, startup recovery, or permanent notification-delivery degradation.</li>
              </Bullets>
              <H3>Delivery model</H3>
              <Steps>
                <li>The originating transaction inserts an alert row and payload.</li>
                <li>The in-process dispatcher resolves matching email recipients and Teams endpoints.</li>
                <li>It applies per-target de-duplication and rate limits where allowed.</li>
                <li>Each sent, failed, suppressed, bounced, or retryable outcome is recorded.</li>
              </Steps>
              <p>
                Normal repeated events use a ten-minute de-duplication window and a default
                per-target cap of 20 deliveries/hour. Transport errors retry with backoff; five
                failures create a permanent-delivery meta-alert. Failed/uncertain actions, arming
                changes, automatic/startup degradation, and security events bypass suppression and
                rate limits.
              </p>
              <H3>Configuration</H3>
              <Bullets>
                <li>Email transport credentials are controller environment settings; recipients and subscriptions are managed in the app.</li>
                <li>Teams incoming-webhook URLs are write-only and encrypted; the API never returns the stored URL.</li>
                <li>A subscription can match one event type or all events. Use test-send after every new target.</li>
                <li>Critical events additionally fan out to verified admin-tier recipients.</li>
              </Bullets>
              <p>Manage channels in the Notifications card on <AppLink to="/settings">Settings</AppLink>.</p>
            </DocSection>
          )}

          {show("settings") && (
            <DocSection
              id="settings"
              title="Settings and arming"
              summary="Settings contains the highest-consequence global controls; changes are permission-checked, audited, and alerted."
            >
              <H3>Operating mode</H3>
              <p>
                Observe is read-only/alert-only for mitigation execution. Switching to Enforce makes
                execution possible but does not bypass any other gate. Arming from Observe to Enforce
                requires fresh password and TOTP in the same request. Returning to Observe is an
                immediate disarm and does not require step-up.
              </p>
              <H3>Automatic reroutes</H3>
              <p>
                The global switch is the master permission for rule-driven automatic actions. Turning
                it on requires fresh password and TOTP. Turning it off does not affect deliberate
                manual actions, but Observe mode blocks those too.
              </p>
              <H3>Global maintenance lock</H3>
              <p>
                Use the lock before planned router/upstream work or while investigating unsafe state.
                It blocks all new mitigations without stopping telemetry, detection, or alerting. Lock
                changes are audited and alerted.
              </p>
              <H3>RTBH community catalog</H3>
              <p>
                Superadmins manage approved standard (<Code>X:Y</Code>) or large
                (<Code>X:Y:Z</Code>) BGP communities and their matching static-route tag. Blackhole
                templates choose from this catalog; a typed but unapproved tag is not accepted.
              </p>
              <H3>A safe arming review</H3>
              <CheckList>
                <Check>All enabled devices have fresh SNMP inventory and stable, capable SSH access.</Check>
                <Check>Announced-prefix and BGP discovery reflects current router configuration.</Check>
                <Check>Critical interfaces are protected.</Check>
                <Check>Every enabled action has been reviewed in observe mode with its rollback.</Check>
                <Check>Rule persistence and recovery were validated against real traffic without false firing.</Check>
                <Check>Notifications and an operator response path have been tested.</Check>
                <Check>No unresolved failed/uncertain actions or unexplained locks remain.</Check>
              </CheckList>
              <p>Open <AppLink to="/settings">Settings</AppLink>.</p>
            </DocSection>
          )}

          {show("incidents") && (
            <DocSection
              id="incidents"
              title="Incidents and recovery"
              summary="Use evidence from the controller and the router; uncertainty is intentionally resolved by a human, not guessed away."
            >
              <H3>Attack detected but no action ran</H3>
              <Steps>
                <li>Confirm whether mode is Observe. If so, no execution is expected.</li>
                <li>Check the rule's Manual apply and Auto toggles, attached enabled actions, and template automatic policy.</li>
                <li>Read the action result's blocked reason.</li>
                <li>Check global/device locks, unresolved uncertainty, cooldowns, and the global rate window.</li>
                <li>Check device SSH status, command access, stability, host key, and fresh routing inventory.</li>
                <li>For flow actions, check exporter enrollment, sampling confidence, SNMP corroboration, and the separate flow-auto switch.</li>
              </Steps>
              <H3>Telemetry is stale</H3>
              <p>
                Treat the last value as historical. Test SNMP, inspect the device's last error,
                management reachability, ACLs, community, and polling interval. A first successful
                poll restores a baseline; a following valid poll restores rates. Detection correctly
                remains suppressed until trustworthy data exists.
              </p>
              <H3>An action is uncertain</H3>
              <Steps>
                <li>Leave the device lock in place.</li>
                <li>Review the action detail, commands, last response, and intended verification.</li>
                <li>Log into the router independently and run the relevant show command: route, BGP neighbor, advertised routes, route-map assignment, or interface configuration/state.</li>
                <li>Decide whether the desired configuration is present, absent, or partial.</li>
                <li>Acknowledge uncertainty in History only after that check. Acknowledgement marks the original action failed/acknowledged; it does not claim recovered success.</li>
                <li>If configuration must be undone, clear the linked safety lock through acknowledgement, then run the previewed rollback as a new action.</li>
              </Steps>
              <Callout tone="warning" title="Why a crash creates uncertainty">
                A command may have reached the router just before the process or connection failed.
                On startup, every action left planned, pending, running, or verifying is atomically
                marked uncertain, linked to a device lock, audited, and alerted. Automatic startup
                re-verification is not implemented.
              </Callout>
              <H3>Controller or database unavailable</H3>
              <Bullets>
                <li>The static UI may still load while API data/actions fail. Do not trust previously rendered data as live.</li>
                <li>If the database cannot persist action state, the controller must not reroute.</li>
                <li>After recovery, inspect startup recovery alerts, uncertain actions, locks, and service logs before resuming operation.</li>
              </Bullets>
              <H3>Mitigation must be lifted</H3>
              <p>
                Open the succeeded item in History, preview its paired rollback, and verify the
                inverse commands and show check. Mitigations have no automatic expiry; clearing a
                detection rule does not withdraw router configuration.
              </p>
            </DocSection>
          )}

          {show("audit") && (
            <DocSection
              id="audit"
              title="Audit and forensics"
              summary="Audit entries identify who changed what and from where; mitigation detail supplies the lower-level execution evidence."
            >
              <H3>What is recorded</H3>
              <Bullets>
                <li>Login, failure, lockout, TOTP enrollment/reset, recovery-code use, logout, and session-impacting changes.</li>
                <li>Device, rule, template-related configuration, notification, user, lock, and setting changes.</li>
                <li>Mitigation decisions and lifecycle transitions, including trigger type and actor.</li>
                <li>Uncertain acknowledgement and safety-state changes.</li>
              </Bullets>
              <p>
                Entries include time, actor, action, subject, trusted client IP, and structured
                details. The displayed IP is trustworthy only because the supported production path
                is Cloudflare → restricted Nginx origin → loopback controller.
              </p>
              <H3>Reconstructing “why did this happen?”</H3>
              <Steps>
                <li>Find the fired rule and compare observed value, operator, threshold, persistence, and target scope.</li>
                <li>Check sample freshness/confidence and the rule's prior state to confirm a rising edge.</li>
                <li>Read the alert payload for would-run, executed, or blocked action outcomes.</li>
                <li>Open each mitigation row and follow planned → running → verifying → terminal state.</li>
                <li>Inspect step requests/responses and verification evidence.</li>
                <li>Correlate settings, lock, user, device, or rule edits in Audit around the same time.</li>
                <li>Compare against router logs/state when controller evidence is uncertain.</li>
              </Steps>
              <p>
                Use <AppLink to="/audit">Audit</AppLink> for actor/configuration history and
                <AppLink to="/mitigations">Mitigation History</AppLink> for execution evidence.
                Audit/security trails and reroute state are intentionally not blanket-pruned by the
                short telemetry retention job.
              </p>
            </DocSection>
          )}

          {show("architecture") && (
            <DocSection
              id="architecture"
              title="How the system is built"
              summary="One stateless browser app and one stateful controller keep authority and recovery behavior explicit."
            >
              <div className="rounded-lg border bg-muted/20 p-4 font-mono text-xs leading-6 md:text-sm">
                Browser SPA
                <br />
                &nbsp;&nbsp;↓ HTTPS through Cloudflare and Nginx
                <br />
                Rust controller API on 127.0.0.1:9277
                <br />
                &nbsp;&nbsp;├─ MariaDB: system of record
                <br />
                &nbsp;&nbsp;├─ SNMP → enrolled routers (read-only telemetry/discovery)
                <br />
                &nbsp;&nbsp;├─ SSH → Cisco IOS (allowlisted execution + verification)
                <br />
                &nbsp;&nbsp;├─ UDP ← NetFlow v9 / sFlow v5 (optional)
                <br />
                &nbsp;&nbsp;└─ SMTP / Teams webhooks → notifications
              </div>
              <H3>Browser</H3>
              <p>
                The React SPA is static and has no operational source of truth. It uses same-origin
                credentialed API requests, displays server responses, and redirects to login when an
                authenticated request loses its session. Router credentials and session tokens are
                not exposed to application JavaScript.
              </p>
              <H3>Controller</H3>
              <p>
                One Rust process owns authentication/RBAC, the REST API, scheduling, SNMP and flow
                ingestion, detection, mitigation execution, alert dispatch, retention, startup
                recovery, and database migrations. Per-device tasks are independent and jittered so
                one failed router does not stop collection from others.
              </p>
              <H3>Database</H3>
              <p>
                MariaDB is the system of record and the controller is its only operational writer.
                Current samples, retained history, rule state, action state, locks, cooldowns, alerts,
                sessions, configuration, and audit evidence survive browser and service restarts.
              </p>
              <H3>Network trust boundaries</H3>
              <Bullets>
                <li>The HTTP API refuses a non-loopback bind; public access is only through Nginx.</li>
                <li>The origin should accept HTTPS only from current Cloudflare address ranges.</li>
                <li>SNMP v2c is cleartext on the wire; isolate and ACL the management network and use unique read-only communities.</li>
                <li>Legacy IOS SSH algorithms exist for compatibility and should remain confined to the management network.</li>
                <li>Flow UDP ingress requires explicit network anti-spoofing controls.</li>
              </Bullets>
              <H3>Secrets</H3>
              <p>
                Passwords use Argon2id. Device and TOTP secrets use AES-256-GCM under the deployment's
                <Code>SECRETS_KEY</Code>. Session cookies hold a random token while the database holds
                its hash. Losing the encryption key makes stored device secrets unrecoverable, so the
                database, environment file, and configuration must be backed up together and protected.
              </p>
            </DocSection>
          )}

          {show("limits") && (
            <DocSection
              id="limits"
              title="Current limits"
              summary="These boundaries are intentional; do not operate the app as if a planned or de-scoped capability exists."
            >
              <Bullets>
                <li>Only Cisco IOS device-CLI execution is implemented. There is no Cloudflare API, standalone BGP speaker, FlowSpec provider, or scrubber-provider adapter.</li>
                <li>SNMP v2c is implemented; SNMPv3 is a typed but unsupported path.</li>
                <li>NetFlow v9 and sFlow v5 are implemented; IPFIX is not.</li>
                <li>There is no continuous BGP feed. Verification uses on-router show commands.</li>
                <li>There is no arbitrary command console.</li>
                <li>There is no automatic mitigation expiry. Use explicit verified rollback.</li>
                <li>There is no automatic SSH re-verification of uncertain actions at startup.</li>
                <li>Rules use absolute thresholds; learned anomaly/baseline rules are not implemented.</li>
                <li>SNMP gives interface volume, not SYN rate, source distribution, or application-layer signatures.</li>
                <li>The controller is a single service, not a distributed high-availability cluster.</li>
                <li>Short-term samples, buckets, alerts, and rule events are retained according to configured windows; the shipped window is two days.</li>
              </Bullets>
              <Callout tone="info" title="Read “not implemented” literally">
                A visible data field, old design note, or template enum does not prove an executor or
                safety path exists. The UI and current controller behavior are the operational contract.
              </Callout>
            </DocSection>
          )}

          {show("glossary") && (
            <DocSection
              id="glossary"
              title="Glossary"
              summary="Short definitions for language used in the interface and this handbook."
            >
              <TopicTable>
                <thead><tr><th className={thClass}>Term</th><th className={thClass}>Definition</th></tr></thead>
                <tbody>
                  {[
                    ["Announced space", "Prefixes recently discovered from a router's BGP network configuration; used to contain mitigation targets."],
                    ["Automatic action", "A mitigation launched from a rule's firing edge without an operator executing it."],
                    ["Corroboration", "Independent same-interface SNMP evidence used to sanity-check sampling-scaled flow volume."],
                    ["Cooldown", "A time-based throttle after a device or rule action; it is not a lock and expires naturally."],
                    ["Enforce", "Operating mode in which execution may occur if every other gate passes."],
                    ["Firing edge", "The one transition from matching to firing that emits the fired event and considers automatic actions."],
                    ["Lock", "A persisted hard block on global or device-scoped action scheduling until explicitly cleared/acknowledged."],
                    ["Null0", "A router discard interface. A static route to Null0 drops matching destination traffic locally."],
                    ["Observe", "Default mode: collect, detect, alert, and render plans, but execute no mitigation."],
                    ["Protected interface", "A critical interface that disruptive shutdown and MSS-add templates are forbidden to target."],
                    ["Preview token", "A short-lived, single-use proof that an enforce-mode operator saw the exact unchanged server-rendered plan."],
                    ["RTBH", "Remotely Triggered Black Hole: advertise a tagged route/community so an upstream discards the destination traffic."],
                    ["Rollback", "A new, independently previewed and verified action that applies a template's inverse."],
                    ["Stale", "Older than the configured trust window; excluded from rule evaluation or action inventory resolution."],
                    ["Uncertain", "The controller cannot prove final device state. The related device is locked pending manual verification."],
                    ["Verification", "A separate read-only show command whose result must prove the intended state."],
                    ["Would-run plan", "Exact rendered commands and verification/rollback information returned without execution."],
                  ].map(([term, definition]) => (
                    <tr key={term}><td className={tdClass}><strong>{term}</strong></td><td className={tdClass}>{definition}</td></tr>
                  ))}
                </tbody>
              </TopicTable>
              <p className="text-muted-foreground">
                If an operational result conflicts with an assumption, trust the current server state,
                block reason, action evidence, and router verification—not the assumption.
              </p>
            </DocSection>
          )}
        </div>
      </div>
    </div>
  );
}
