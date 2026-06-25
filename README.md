# Azure Engineering — operational tools hub

A self-hosted dashboard that scans an Azure tenant for operational and cost-governance
issues and visualizes the results locally. It's a set of PowerShell scanners and
single-file HTML dashboards served by a small local web server — no build step, no
package manager, no database.

The tools in the hub:

| Tool | What it finds |
|------|---------------|
| **Idle Resource Scanner** | Resource groups with no recent activity, metrics, or changes — with cost, locks, orphaned resources, and a recommended action. |
| **Privileged Access Scanner** | Standing privileged role assignments (Owner / Contributor / UAA / RBAC Admin) held directly by users and service principals. |
| **Entra User Scanner** | Stale, orphaned, or risky directory accounts. |
| **Tag Auditor** | Objects whose *effective* (inherited) tags violate your required-tag rules. |
| **Log Analytics Cost Projector** | Per-table cost projection for a workspace from billable ingestion + retention. |
| **Quota Usage Scanner** | Compute / Network / Storage usage-vs-limit, flagged Critical / Warning, with an action per quota. |

## Prerequisites

- **PowerShell 7+**
- The **`ThreadJob`** module and the Az modules `Az.Accounts`, `Az.Resources`,
  `Az.Monitor`, `Az.CostManagement`, `Az.ResourceGraph` (and `Az.ManagementGroups` for
  management-group scope).
- Azure permissions: **Reader** + **Cost Management Reader** per subscription. (The Entra
  scanner additionally needs Microsoft Graph directory read; the Log Analytics projector
  also needs **Log Analytics Reader**.)

Verify your machine before the first run:

```powershell
./Test-Prerequisites.ps1
```

## Running the dashboard

Authentication happens **in your terminal**, before the dashboard starts. Sign in with
`Connect-AzAccount`, then launch the server **in the same PowerShell session** so it
inherits your Azure context:

```powershell
# 1. Sign in to Azure (opens your browser). Once per session.
Connect-AzAccount

# 2. (optional) choose a default subscription — you can also switch it from the
#    dashboard header once it's running.
Set-AzContext -Subscription "<subscription-name-or-id>"

# 3. Start the dashboard, then open http://localhost:8080
./Start-Dashboard.ps1
```

Custom port or a sequential (non-parallel) scan:

```powershell
./Start-Dashboard.ps1 -Port 9000 -ThrottleLimit 1
```

Your Azure context is held **in process memory only** — no credentials are written to
disk. The dashboard header shows the signed-in account and lets you switch the active
subscription.

### Stopping the dashboard

Click **■ Stop** in the dashboard header (or press `Ctrl+C` in the terminal). This shuts
the server down but leaves your terminal's `Connect-AzAccount` session intact, so you can
re-run `./Start-Dashboard.ps1` immediately. To fully sign out, run `Disconnect-AzAccount`.

## Targeting a scope

Each scanner page opens with a **⚙ Scanner configuration** card. Pick a target —
whole tenant, a **management group**, a **subscription**, or a **resource group** (where
applicable) — then **Run Scan**. The scan only covers the chosen scope.

## Project layout

```
Start-Dashboard.ps1   New-HubTool.ps1   Test-Prerequisites.ps1
scanners/   the PowerShell scanners (Invoke-*Scan.ps1)
web/        the single-file HTML dashboards (home.html + one per tool)
data/       runtime scan JSON — regenerated each scan, gitignored
tests/      smoke-test suite
```

## Running a scanner without the dashboard

Each scanner can run standalone and writes its JSON results into `data/`:

```powershell
./scanners/Invoke-AzureIdleScan.ps1 -SingleSubscriptionId <subId>
./scanners/Invoke-TagComplianceScan.ps1 -RequiredTags Environment,Owner,CostCenter
./scanners/Invoke-QuotaScan.ps1
```

## Adding a tool / running the tests

```powershell
# Scaffold a new tool (creates the scanner + page, prints the wiring to paste):
./New-HubTool.ps1 -Name "Cost Anomaly Detector" -Slug cost-anomaly -ApiPrefix anomaly -Icon 💸

# Smoke tests (contract checks + a brief server boot):
./tests/Run-Tests.ps1                 # all
./tests/Run-Tests.ps1 -SkipServer     # contract-only (no Az/server needed)
```

See [CLAUDE.md](CLAUDE.md) for the full architecture, scanner internals, and conventions.
