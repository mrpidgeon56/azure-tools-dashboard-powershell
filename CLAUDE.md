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

# Scanners live in scanners/ and write their JSON into data/ (gitignored). Standalone, no dashboard:
./scanners/Invoke-AzureIdleScan.ps1 -SingleSubscriptionId <subId>   # fast: one subscription
./scanners/Invoke-AzureIdleScan.ps1 -Incremental                    # reuse cached per-RG results
./scanners/Invoke-AzureIdleScan.ps1 -SkipMetrics -SkipCostData      # if those perms/queries are unavailable

# Tag Auditor standalone (writes data/tag-scan-results.json):
./scanners/Invoke-TagComplianceScan.ps1 -RequiredTags Environment,Owner,CostCenter

# Log Analytics Cost Projector standalone (writes data/la-cost-scan-results.json):
./scanners/Invoke-LogAnalyticsCostScan.ps1 -SubscriptionId <subId> -ResourceGroup <rg> -WorkspaceName <ws>

# Quota Usage Scanner standalone (writes data/quota-scan-results.json):
./scanners/Invoke-QuotaScan.ps1                                     # all subscriptions
./scanners/Invoke-QuotaScan.ps1 -SingleSubscriptionId <subId>       # one subscription

# Pre-flight: verify PowerShell 7+ and required Az modules are installed before starting.
./Test-Prerequisites.ps1

# Smoke tests (contract checks always; server integration boots the server briefly):
./tests/Run-Tests.ps1                 # all
./tests/Run-Tests.ps1 -SkipServer     # contract-only (no Az/server needed)

# Scaffold a new tool (creates the scanner + page, prints the server/home wiring):
./New-HubTool.ps1 -Name "Cost Anomaly Detector" -Slug cost-anomaly -ApiPrefix anomaly -Icon 💸
./New-HubTool.ps1 -Slug cost-anomaly -Remove   # tear the generated files back out
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

**Auth is terminal-driven and process-memory-only.** Sign in *before* launch with
`Connect-AzAccount`, then start `./Start-Dashboard.ps1` **in the same PowerShell session** so
it inherits the live context (held in process memory only — no credentials on disk). Because
scans run in-process (see below), they inherit this context too. `GET /api/auth/status`
reports the active account; the home-page header shows it and offers a subscription switch
(`POST /api/auth/subscription`). The header **■ Stop** button → `POST /api/shutdown` calls
`$listener.Stop()` to shut the server down **without** disconnecting (your terminal session
stays signed in — re-run `./Start-Dashboard.ps1` to start again). A legacy
`POST /api/auth/logout` (Disconnect + Clear + stop) still exists but is no longer wired to the
UI; there is no in-dashboard interactive sign-in.

### Project layout

```
Start-Dashboard.ps1   New-HubTool.ps1   Test-Prerequisites.ps1   (entry points, repo root)
scanners/   Invoke-*Scan.ps1            (the PowerShell scanners)
web/        home.html + one <tool>.html per tool   (single-file dashboards)
data/       *-scan-{results,progress}.json          (runtime artifacts — gitignored)
tests/      Run-Tests.ps1 + Test-Contracts.ps1 + Test-Server.ps1
```
The server resolves pages under `web/`, scanners under `scanners/`, and writes results to
`data/` (created at startup if absent). Scanners default `-OutputPath` to `../data/`.

### Previewing the UI without Azure

`.claude/launch.json` defines a `dashboard` config that runs `python3 -m http.server 8081`
from the repo root. This serves files statically but has **no `/api/*` endpoints**, so a page
loads its empty state. Open `http://localhost:8081/web/<tool>.html`; to exercise rendering,
fetch a `data/*-scan-results.json` (e.g. `/data/scan-results.json`) and call `applyData(json)`
in the page console.

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
  workspace pickers), Quota Usage = `/api/quota/*`; plus the shared `/api/auth/*`,
  `/api/subscriptions`, `/api/managementgroups`, and `/api/resourcegroups?subscriptionId=`. Scans run via **`Start-ThreadJob`, not
  `Start-Job`** — ThreadJob is in-process, so the scan inherits the already-loaded Az modules
  and live Az context (no token re-auth, no MSAL-cache issues in a child process). The
  `POST /api/scan` body is `{ scopeType?, managementGroupId?, singleSubscriptionId?, resourceGroup?, lookbackDays? }`.
  - **Security guards** apply to every route: a Host-header check, a same-origin/CSRF check
    (`Test-SameOrigin`) on all non-GET `/api` requests, a request-body size cap, and
    `X-Content-Type-Options: nosniff`. New routes inherit these automatically.
  - **Scan scope targeting** is uniform across the resource-scanning tools. Each tool's page
    has a top **"⚙ Scanner configuration" card** with a `scopeType` selector
    (`All` / `ManagementGroup` / `Subscription` / `ResourceGroup`) and dependent pickers fed by
    the shared `/api/managementgroups` and `/api/resourcegroups?subscriptionId=` (cascading
    Subscription → RG) endpoints. The scan body carries `scopeType` + `managementGroupId` /
    `singleSubscriptionId` / `resourceGroup`; the server splats matching `-ScopeType`,
    `-ManagementGroupId`, `-SingleSubscriptionId`, `-ResourceGroup` params into the scanner.
    Scanners resolve scope via Resource Graph (`Search-AzGraph -ManagementGroup` recurses an MG;
    `subscriptionId`/`resourceGroup` filters narrow to a sub/RG) and stay **backward-compatible**
    (default `ScopeType=All`; a lone `-SingleSubscriptionId` still scans just that sub). Per-tool
    matrix: idle / Privileged Access / Tag Auditor = MG+Sub+RG; Quota = MG+Sub (RG is not
    meaningful — quotas are per-subscription/region); Log Analytics keeps its
    Subscription → RG → Workspace cascade; Entra is directory-wide (no Azure scope).

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
  overrides them (its (0,1,1) specificity beats `:root`). Every page shares an identical
  **core** token set (see the Design language section), so one `html.light` block — which
  overrides only the seven structural tokens (`--bg`, `--surface`, `--surface2`, `--border`,
  `--text`, `--muted`, `--accent`) — themes a page uniformly; tools may add a few domain-accent
  tokens on top.
- `*-scan-results.json` / `*-scan-progress.json` are runtime artifacts written by the scanners.
- When adding a new tool to the hub: **run `./New-HubTool.ps1 -Name "..." -Slug ... -ApiPrefix ...`**.
  It scaffolds `scanners/Invoke-<Name>Scan.ps1` (standard scope params + progress scaffolding +
  the `{ ScanMetadata, Items, Errors }` envelope) and `web/<slug>.html` (cloned from the
  reference page, identifiers swapped), then prints the exact `Start-Dashboard.ps1` +
  `web/home.html` wiring to paste — the `$pageRoutes` entry, the
  `/api/<tool>/{results,status,scan,scan/cancel}` quartet, and the home card. Then fill the
  TODOs (scan body; cards/columns/`renderTable`) and run `./tests/Run-Tests.ps1` — the contract
  test enforces the conventions below (scope params, the standard page helpers, "every POST
  fetch sends a body"). The Design language section below is the contract every page follows.

## Design language (for new pages)

Every page is a single self-contained HTML file (vanilla HTML/CSS/JS — no framework, bundler,
or external assets). New pages must match the existing ones; the fastest correct path is to
**clone the most similar page** (`quota-usage.html` is the cleanest reference) and swap the data
shape. **Browser baseline:** the pages use untranspiled modern JS/CSS (optional chaining `?.`,
nullish `??`, `inset`, etc.) and there is deliberately no build step, so they target evergreen
browsers (Chromium/Edge ≥ 80, Firefox ≥ 74, Safari ≥ 13.4 — 2020+); older/locked-down webviews
will fail to parse rather than degrade. The shared contract:

- **Design tokens** — all colour/spacing comes from CSS custom properties on `:root` (dark
  defaults) with an `html.light` override block. The **core set every page defines identically**:
  `--bg` (page), `--surface` / `--surface2` (cards / insets), `--border`, `--text`, `--muted`
  (secondary text), `--accent` (primary / links / active), `--danger`, `--warn`, `--ok`,
  `--radius` (8px), `--font` (`"Inter","Segoe UI",system-ui,sans-serif`). Add domain-accent
  tokens only as needed (e.g. `--sub` purple, `--rg` cyan, `--res` grey for subscription /
  resource-group / resource; `--cost`). Never hard-code a hex value in a rule — reference a token.
- **Colour semantics** — `--accent` = primary action / links / active filter; `--danger` =
  critical / flagged / destructive; `--warn` = warning; `--ok` = healthy / compliant / savings;
  the domain tokens colour scope pills (sub / RG / resource). Severity always maps to
  danger→warn→ok in that order.
- **Visual feel** — dark-first; 14px base; cards are `--surface` with a 1px `--border` and
  `--radius` corners, 16–18px padding; section micro-labels are 11px UPPERCASE `--muted` with
  ~.5px letter-spacing; numbers use `font-variant-numeric: tabular-nums`; hover/focus
  transitions ~.15s; the `--accent` outline marks focus and active state.
- **Page skeleton (in order)** — (1) a head `<script>` that applies `azureHub.theme` before
  first paint (FOUC-free); (2) sticky `header` = emoji logo + `.crumbs` (`Azure Engineering ›
  Tool`) + `h1` + `.header-actions` (↻ refresh, Cancel, sometimes a primary action); (3)
  `main` (max-width ~1320px, centred); (4) a top **`.scan-config` "⚙ Scanner configuration"
  card** (scope selector — see the Scan-scope subsection above); (5) `.empty` state, shown only
  while `body.needs-data`; (6) `.scan-banner` progress; (7) `.cards` summary tiles
  (`.card` → `.card-label` / `.card-value` / `.card-sub`, with semantic modifier classes like
  `.flagged` / `.warn` / `.ok`); (8) optional `.heatmap-wrap` click-to-filter heatmap; (9)
  `.toolbar` = `.search-wrap` (🔍 icon + input) + toggles + `⬇ Export CSV (n)`; (10)
  `.filter-summary` ("Showing x–y of n") on its **own line below** the toolbar; (11)
  `.table-wrap` with a `<table>` (sticky `th`, sortable headers, funnel column filters); (12)
  `.pager`; (13) a slide-in detail panel (`.overlay` + `.detail`); (14) fixed bottom-left
  `.theme-toggle`.
- **Reusable components (copy, don't reinvent)** — the scope card, summary `.cards`, the
  `.search-wrap`+icon search, funnel column filters (`.filter-icon` + `.col-filter-pop`,
  multi-select), severity `.status-pill`, the slide-in detail panel with ‹/›/✕ + arrow-key
  nav, the pager, and CSV export **with the formula-injection guard** (`'`-prefix any cell
  matching `^[=+\-@\t\r]`).
- **Iconography** — emoji set the tone: a per-tool logo glyph, `▶` run, `■` stop, `↻` refresh,
  `⚙` configuration, `⬇` export, `🔍` search, the funnel SVG for filters, `🌙`/`☀️` for the theme
  toggle.
- **JS conventions** — render through a single `applyData(json)` gate that requires
  `json.ScanMetadata` **and** a non-empty results array, else add `needs-data` and bail; wrap
  every scanner array field in `asArray()` (ConvertTo-Json scalar collapse); HTML-escape every
  interpolated value with `esc()` (PA's `escapeHtml` is a legacy outlier — prefer `esc`); derive
  the table, detail panel, and CSV from one `getFilteredRows()`; poll `/api/<tool>/status` while
  a scan runs. **Gotcha:** an element toggled via the `hidden` attribute also needs an explicit
  `[hidden] { display: none }` rule whenever it carries an author `display` (e.g. `display:flex`),
  which otherwise wins over the UA `hidden` style.
