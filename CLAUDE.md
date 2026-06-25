# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A self-hosted "Azure Engineering" operational-tools hub. The flagship tool scans every
subscription in an Azure tenant for **idle resource groups** (no activity across Activity
Log, resource metrics, and last-modified time), enriches them with cost, Azure Advisor,
resource locks, orphaned-resource and managed/system-RG detection, then visualizes the
results in a local web dashboard.

There is **no build system, no package manager, and no test suite**. The app is a set of
PowerShell scanners + single-file HTML dashboards that communicate through JSON files on
disk. Additional tools in the hub: a Privileged Access scanner, an Entra user scanner, a
**Tag Auditor** (`Invoke-TagComplianceScan.ps1` / `tag-compliance.html`) that recurses
subscriptions → resource groups → resources via Azure Resource Graph and checks each
object's *effective* (inherited) tags against UI-supplied required-tag rules, and a
**Log Analytics Cost Projector** (`Invoke-LogAnalyticsCostScan.ps1` /
`log-analytics-cost.html`) that costs a chosen workspace's tables from their billable
ingestion + current retention settings, priced live from the Azure Retail Prices API, and a
**Quota Usage Scanner** (`Invoke-QuotaScan.ps1` / `quota-usage.html`) that checks
Compute/Network/Storage usage-vs-limit (the ARM "usages" APIs) across only the regions each
subscription actually uses (discovered via Resource Graph), flags quotas Critical/Warning by
threshold, and recommends an action per quota.

## Running it

```powershell
# Full app: starts the HTTP server, prompts Azure sign-in if needed, serves the dashboard.
./Start-Dashboard.ps1                 # then open http://localhost:8080
./Start-Dashboard.ps1 -Port 9000 -ThrottleLimit 1   # custom port; sequential (non-parallel) scan

# Run the scanner standalone (writes scan-results.json), no dashboard:
./Invoke-AzureIdleScan.ps1 -SingleSubscriptionId <subId>   # fast: one subscription
./Invoke-AzureIdleScan.ps1 -Incremental                    # reuse cached per-RG results
./Invoke-AzureIdleScan.ps1 -SkipMetrics -SkipCostData      # if those perms/queries are unavailable

# Tag Auditor standalone (writes tag-scan-results.json):
./Invoke-TagComplianceScan.ps1 -RequiredTags Environment,Owner,CostCenter

# Log Analytics Cost Projector standalone (writes la-cost-scan-results.json):
./Invoke-LogAnalyticsCostScan.ps1 -SubscriptionId <subId> -ResourceGroup <rg> -WorkspaceName <ws>

# Quota Usage Scanner standalone (writes quota-scan-results.json):
./Invoke-QuotaScan.ps1                                     # all subscriptions
./Invoke-QuotaScan.ps1 -SingleSubscriptionId <subId>       # one subscription

# Pre-flight: verify PowerShell 7+ and required Az modules are installed before starting.
./Test-Prerequisites.ps1
```

Requires PowerShell 7+, the `ThreadJob` module, and Az modules (`Az.Accounts`,
`Az.Resources`, `Az.Monitor`, `Az.CostManagement`; `Az.ManagementGroups` optional, for
management-group scope in the Privileged Access scanner). Per-subscription permissions:
Reader + Cost Management Reader. The Tag Auditor additionally uses `Az.ResourceGraph` and
needs only **Reader** (no Microsoft Graph permission — unlike the Entra scanner). The Log
Analytics Cost Projector needs **Reader** + **Log Analytics Reader** (the latter to run the
billable-volume `Usage` query); it lists workspaces via Resource Graph and reads
tables/retention + retail prices over REST using the in-memory Az token — no extra module
beyond `Az.Accounts`/`Az.ResourceGraph`. The Quota Usage Scanner needs only **Reader**: it
discovers active regions via `Az.ResourceGraph` and reads the per-region usages ARM APIs
directly with the in-memory Az token (no Cost Management or Graph permission).

**Auth is interactive and process-memory-only.** Sign-in/out happens *from the dashboard*
(`POST /api/auth/login` → `Connect-AzAccount` via system browser; `POST /api/auth/logout` →
`Disconnect-AzAccount` + `Clear-AzContext`); `GET /api/auth/status` reports session state.
No credentials are ever stored on disk. Because scans run in-process (see below), they
inherit this live context. **Signing out also stops the server** — `/api/auth/logout` calls
`$listener.Stop()` after clearing the context, so the home page treats sign-out as a full
shutdown (it shows a "dashboard stopped" state); restart with `./Start-Dashboard.ps1`.

### Previewing the UI without Azure

`.claude/launch.json` defines a `dashboard` config that runs `python3 -m http.server 8081`.
This serves the HTML statically but has **no `/api/*` endpoints**, so the page loads its
empty state. To exercise rendering, fetch the committed `scan-results.json` (served
statically at `/scan-results.json`) and call `applyData(json)` in the page console.

## Architecture

Three components, decoupled by two on-disk JSON files:

```
Invoke-AzureIdleScan.ps1 ──writes──> scan-results.json  ──/api/results──> index.html
        │                                                                     ▲
        └──────writes──> scan-progress.json ──/api/status──> (live progress) ─┘
                          ▲
Start-Dashboard.ps1 ──Start-ThreadJob──> runs the scanner, serves HTML + API
```

- **`Start-Dashboard.ps1`** — a `System.Net.HttpListener` server. A `$pageRoutes` table maps
  clean URLs to files (`""`→`home.html`, `/idle-resources`→`index.html`,
  `/privileged-access`, `/entra-users`, `/tag-compliance`, `/log-analytics-cost`,
  `/quota-usage`). **Each
  tool exposes the same endpoint quartet**, namespaced by tool: idle =
  `/api/{results,status,scan,scan/cancel}`, Privileged Access = `/api/pa/*`, Entra =
  `/api/entra/*`, Tag Auditor = `/api/tags/*`, Log Analytics Cost = `/api/la/*` (which also
  adds `GET /api/la/workspaces?subscriptionId=` to drive the cascading subscription → RG →
  workspace pickers), Quota Usage = `/api/quota/*`; plus the shared `/api/auth/*` and `/api/subscriptions`. Scans run via **`Start-ThreadJob`, not
  `Start-Job`** — ThreadJob is in-process, so the scan inherits the already-loaded Az modules
  and live Az context (no token re-auth, no MSAL-cache issues in a child process). The
  `POST /api/scan` body is `{ singleSubscriptionId?, lookbackDays? }`.
  - **Security guards** apply to every route: a Host-header check, a same-origin/CSRF check
    (`Test-SameOrigin`) on all non-GET `/api` requests, a request-body size cap, and
    `X-Content-Type-Options: nosniff`. New routes inherit these automatically.

- **`Invoke-AzureIdleScan.ps1`** — the scanner. Organized into `#region` blocks (helpers /
  main scan / write output). Key performance design:
  - **Subscription-level batch fetches** done once per subscription and reused across all its
    RGs: one Resource Graph query for the full inventory (`Get-SubscriptionResourceMap`), one
    Cost Management query (`Get-SubscriptionCostByRg`), one Advisor query
    (`Get-SubscriptionAdvisorRecommendations`). Per-RG fallbacks exist when these are
    unavailable.
  - **Parallel per-RG scan** via `ForEach-Object -Parallel -ThrottleLimit`. PowerShell
    runspaces don't see script functions, so their definitions are serialized and re-injected
    into each runspace (see the `$funcDefs` block in the main scan region). A
    `ConcurrentDictionary` shares the principal-name cache across threads.
  - The **consumer pattern**: a producer (sequential or parallel) streams per-RG result
    objects to `$consumeRgResult`, which runs in the main runspace, so all shared-state
    mutation (results list, flagged count, progress) is single-threaded and race-free.
  - **Incremental cache** (`-Incremental`): each RG gets a fingerprint (`Get-RgFingerprint`)
    of its resources; unchanged + fresh RGs reuse the prior `scan-results.json` record.
    NOTE: the fingerprint covers resources only, not `LookbackDays` — changing the window in
    incremental mode will serve stale records.

- **`index.html`** / **`home.html`** — single-file vanilla HTML/CSS/JS (no framework, no
  bundler). `home.html` is the hub; `index.html` is the scanner dashboard.

## Core domain logic

- **Idle flagging** (`Invoke-RgScan`): `IsFlagged = (not managed) AND NOT (hasActivity OR
  hasMetrics OR hasModified)`. Managed/system RGs (`Get-ManagedReason`) are never flagged
  because they look idle but aren't actionable.
- **Recommended action** (`Get-RecommendedAction`) rolls up idle signals + locks + managed
  detection + orphaned resources + cost into a single suggested action (Keep / Review lock /
  Delete / Clean up orphans / Decommission) with potential savings.

## Conventions and gotchas

- **`Set-StrictMode -Version Latest`** is on in every scanner and the server. Accessing a missing property
  throws — check `$obj.PSObject.Properties['Name']` / `-contains` before reading optional
  fields (the `/api/scan` body parser does this).
- **`ConvertTo-Json` collapses a single-element array into a bare scalar.** The frontend
  normalizes every such field back to an array with `asArray()` in `applyData()`. When adding
  a new array field to the scanner output, wrap it in `asArray()` on the client.
- **Frontend single source of truth for the visible rows is `getFilteredRows()`** — the
  table, detail panel, CSV export, and copy-delete-commands all derive from it so they stay
  consistent. Pagination only affects what's *painted*; export/copy/detail-nav operate on the
  full filtered set, and row `onclick` handlers pass the **global** filtered index.
- **`localStorage` keys**: `azureHub.theme` (`'light'`/`'dark'`) is **shared across all
  pages** — every HTML file reads it in a head script before first paint (FOUC-free) and
  the toggle button writes it, so the theme choice is global. Tool-specific keys:
  `azureIdle.columns` (column visibility), `azureIdle.triage` (per-RG
  acknowledge/snooze/dismiss, keyed `subId|rgname`), `avgRgScanMs` (learned per-RG time for
  the next scan's ETA), `tagCompliance.rules` (saved required-tag rules for the Tag Auditor).
- **Theming** is pure CSS custom properties: `:root` holds dark defaults; `html.light`
  overrides them (its (0,1,1) specificity beats `:root`). All pages share identical `:root`
  variable names, so one `html.light` block themes a page uniformly.
- `*-scan-results.json` / `*-scan-progress.json` are runtime artifacts written by the scanners.
- When adding a new tool to the hub: add a `Invoke-*Scan.ps1` scanner, an HTML page, a route
  in the `$pageRoutes` table, the `/api/<tool>/{results,status,scan,scan/cancel}` endpoint
  quartet (copy an existing tool's block), and a card in `home.html`. Carry over the shared
  theme head-script + toggle button so the page participates in global theming.
