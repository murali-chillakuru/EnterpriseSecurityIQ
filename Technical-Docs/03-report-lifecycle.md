# Report Lifecycle

> How reports are created, formatted, stored, and accessed.

**Navigation:** [Index](index-of-tech-docs.md) · [Infrastructure](01-infrastructure-overview.md) · [Assessments](02-assessment-guide.md) · **Reports** · [Manual Setup](04-manual-setup-guide.md) · [Authentication](05-authentication-flow.md) · [API Reference](06-api-reference.md) · [Teams Integration](07-teams-integration.md) · [Troubleshooting](08-troubleshooting.md)

---

## Report Formats

Every assessment can produce reports in multiple formats:

| Format | Extension | Library | Purpose |
|--------|-----------|---------|---------|
| HTML | `.html` | Built-in (string templates) | Interactive browser viewing |
| PDF | `.pdf` | Playwright (headless Chromium) | Print-ready, offline sharing |
| Excel | `.xlsx` | openpyxl | Tabular analysis, pivot tables |
| JSON | `.json` | Built-in | Machine-readable results |
| OSCAL | `.json` | Custom (NIST OSCAL 1.1.2) | US government compliance exchange |
| SARIF | `.sarif` | Custom (SARIF 2.1.0) | GitHub Advanced Security integration |
| Markdown | `.md` | Built-in | Documentation, wiki embedding |
| ZIP | `.zip` | Built-in | Bundle of all reports for a run |

---

## Report Generation Pipeline

```
Assessment completes (results in memory)
       │
       ├──► HTML Report Generator
       │      └── Builds styled HTML with Fluent 2 theme
       │
       ├──► PDF Export (Playwright)
       │      └── Opens HTML in headless Chromium → prints to PDF
       │
       ├──► Excel Export (openpyxl)
       │      ├── Sheet 1: Compliance Report (all controls)
       │      ├── Sheet 2: Gap Analysis (non-compliant only)
       │      └── Sheet 3: Executive Summary (metrics)
       │
       ├──► JSON Export
       │      └── Raw assessment results
       │
       ├──► OSCAL Export (if PostureIQ)
       │      └── NIST OSCAL Assessment Results 1.1.2
       │
       ├──► SARIF Export (if PostureIQ)
       │      └── SARIF 2.1.0 for GitHub Advanced Security
       │
       ├──► Markdown Report
       │      └── Text-based report for docs/wikis
       │
       └──► ZIP Bundle
              └── All of the above in a single download
```

---

## Report Modules

There are two sets of report generators, one generic and one PostureIQ-specific:

### Generic Reports (`AIAgent/app/reports/` — 27 files)

| Module | What It Generates |
|--------|------------------|
| `ai_agent_security_report.py` | AI Agent Security assessment HTML |
| `copilot_readiness_report.py` | Copilot Readiness assessment HTML |
| `custom_report_builder.py` | User-defined custom reports (HTML + Excel) |
| `data_exports.py` | JSON data exports and evidence bundles |
| `data_security_report.py` | Data Security assessment HTML |
| `delta_report.py` | Run-to-run comparison (new/resolved findings) |
| `drift_report_html.py` | Configuration drift detection HTML |
| `evidence_catalog.py` | Full evidence listing with traceability |
| `excel_export.py` | 3-sheet Excel workbook |
| `executive_dashboard.py` | High-level security metrics dashboard |
| `executive_summary.py` | One-page executive summary |
| `gaps_report.py` | Gap analysis (non-compliant controls) |
| `inventory.py` | Azure resource inventory report |
| `markdown_report.py` | Markdown text report |
| `master_report.py` | Combined multi-framework report |
| `methodology_report.py` | Assessment methodology documentation |
| `notifications.py` | Alert/notification formatting |
| `oscal_export.py` | NIST OSCAL 1.1.2 JSON |
| `pdf_export.py` | HTML → PDF via Playwright Chromium |
| `rbac_report.py` | RBAC hierarchy report (interactive tree) |
| `remediation.py` | AI-generated fix scripts |
| `risk_report.py` | Risk analysis HTML |
| `sarif_export.py` | SARIF 2.1.0 for GitHub integration |
| `shared_theme.py` | Common CSS/styling for all HTML reports |
| `trending.py` | Historical score trending charts |

### PostureIQ-Specific Reports (`AIAgent/app/postureiq_reports/` — 20 files)

| Module | What It Generates |
|--------|------------------|
| `data_exports.py` | PostureIQ JSON data exports |
| `delta_report.py` | PostureIQ run comparison |
| `drift_report_html.py` | PostureIQ drift detection |
| `evidence_catalog.py` | PostureIQ evidence listing |
| `excel_export.py` | PostureIQ 3-sheet Excel |
| `executive_dashboard.py` | PostureIQ executive dashboard |
| `html_report.py` | Per-framework HTML report |
| `inventory.py` | PostureIQ resource inventory |
| `json_report.py` | PostureIQ JSON output |
| `markdown_report.py` | PostureIQ Markdown report |
| `master_report.py` | PostureIQ combined report |
| `methodology_report.py` | PostureIQ methodology |
| `oscal_export.py` | PostureIQ OSCAL output |
| `pdf_export.py` | PostureIQ PDF via Playwright |
| `postureiq_report_html.py` | Main PostureIQ HTML report |
| `postureiq_report_md.py` | Main PostureIQ Markdown report |
| `remediation.py` | PostureIQ AI fix scripts |
| `sarif_export.py` | PostureIQ SARIF output |
| `shared_theme.py` | PostureIQ CSS theme |

---

## PDF Generation (Playwright)

PDF generation converts HTML reports to print-quality documents using headless Chromium:

```
HTML file on disk
      │
      ▼
Playwright launches headless Chromium
      │
      ├── Navigate to file:///agent/output/.../report.html
      │   (wait_until="networkidle")
      │
      ├── Expand all <details> elements (auto-open collapsed sections)
      │
      ├── Inject page-break CSS
      │   (prevent breaking inside cards, tables, code blocks)
      │
      └── Print to PDF
          ├── Format: A4 Landscape
          ├── Margins: 12mm top/bottom, 10mm left/right
          ├── Background: enabled (preserves colours)
          └── Output: same directory, .pdf extension
```

Key details:
- **Batch mode**: A single Chromium instance processes all HTML files in a directory, reusing the browser for efficiency
- **Fallback**: If batch mode fails, each file is processed individually with a separate browser instance
- **Content preparation**: `<details>` elements are expanded before printing so no content is hidden
- **Page breaks**: CSS rules prevent breaking inside `.metric-card`, `.detail-panel`, `table`, `pre`, and `.gap-card`

---

## Excel Generation (openpyxl)

Each Excel workbook contains 3 sheets:

### Sheet 1: Compliance Report
- All control results sorted by severity (Critical → Low)
- Columns: ControlId, Title, Domain, Status, Severity, Priority, Compliance %, Description, Remediation, Evidence, Details
- Colour-coded status cells (red = non-compliant, green = compliant, orange = partial)
- Colour-coded severity cells (dark red = critical, red = high, orange = medium, yellow = low)
- Frozen header row, auto-filter enabled

### Sheet 2: Gap Analysis
- Non-compliant and partial findings only
- Deduplicated by ControlId (first occurrence wins)
- Priority labels: P0 (Critical), P1 (High), P2 (Medium), P3 (Low)

### Sheet 3: Executive Summary
- Key metrics: overall score, total controls, passing controls, findings by severity
- Per-domain compliance scores

---

## OSCAL Export

Generates a NIST OSCAL Assessment Results document (version 1.1.2) in JSON format.

```json
{
  "assessment-results": {
    "uuid": "<deterministic UUID5>",
    "metadata": {
      "title": "EnterpriseSecurityIQ Assessment",
      "oscal-version": "1.1.2"
    },
    "results": [{
      "findings": [
        {
          "uuid": "<UUID5 from control_id>",
          "title": "MFA Not Enforced",
          "target": {
            "status": { "state": "not-satisfied" }
          }
        }
      ],
      "observations": [
        {
          "uuid": "<UUID5 from finding key>",
          "props": [
            { "name": "severity", "value": "high" },
            { "name": "resource", "value": "/subscriptions/.../..." }
          ]
        }
      ]
    }]
  }
}
```

Status mapping: `compliant→satisfied`, `non_compliant→not-satisfied`, `partial→other`.

**Use case:** Importing results into GRC platforms (Governance, Risk, Compliance) that support OSCAL.

---

## SARIF Export

Generates a SARIF 2.1.0 document for integration with GitHub Advanced Security and other SAST/DAST tools.

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "EnterpriseSecurityIQ",
        "version": "1.0.0",
        "rules": [
          {
            "id": "NIST-AC-2",
            "shortDescription": { "text": "Account Management" },
            "defaultConfiguration": { "level": "error" }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "NIST-AC-2",
        "level": "error",
        "message": { "text": "Non-compliant: ..." },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": "/subscriptions/.../resourceGroups/..."
            }
          }
        }],
        "fixes": [{
          "description": { "text": "Remediation: ..." }
        }]
      }
    ]
  }]
}
```

Severity mapping: `critical/high→error`, `medium→warning`, `low→note`, `informational→none`.

**Use case:** Upload to GitHub Code Scanning, Azure DevOps, or any SARIF-compatible viewer.

---

## Storage Flow

Reports follow a write-through pattern:

```
Report Generator
      │
      ├── 1. Write to local filesystem
      │      /agent/output/{timestamp}/{framework}/
      │
      └── 2. Upload to Azure Blob Storage
             esiqnewstorage/reports/{timestamp}/{framework}/

User requests report:
      │
      ├── Check local filesystem first
      │     └── Found? → Serve directly (fast)
      │
      └── Not found locally?
            └── Download from blob → save locally → serve
                  └── Not in blob? → 404
```

### Directory Structure

```
output/
  └── 20260422_023002_PM/
       ├── FedRAMP/
       │    ├── fedramp-compliance-report.html
       │    ├── fedramp-compliance-report.pdf
       │    ├── fedramp-compliance-report.xlsx
       │    ├── fedramp-compliance.json
       │    ├── fedramp-gap-analysis.html
       │    ├── fedramp-executive-summary.html
       │    ├── fedramp-remediation.html
       │    └── fedramp-methodology.html
       ├── CIS/
       │    └── (same structure)
       ├── data_exports/
       │    ├── raw-evidence.json
       │    ├── control-results.json
       │    └── assessment-results.json
       ├── compliance-results.sarif
       ├── oscal-assessment-results.json
       ├── drift-report.html
       └── all-postureiq-reports.zip
```

### Blob Storage Configuration

| Setting | Value |
|---------|-------|
| Account | `esiqnewstorage` |
| Container | `reports` |
| Auth | Managed Identity (`DefaultAzureCredential`) |
| Access | `publicNetworkAccess: Enabled` (no VNet) |
| Shared Keys | Disabled (`allowSharedKeyAccess: false`) |
| RBAC Role | `Storage Blob Data Contributor` on managed identity |

---

## Historical Tracking and Delta Analysis

PostureIQ tracks assessment runs over time and can compare results between runs.

### How History Is Stored

```
Blob Storage:
  history/
    {tenant-id}/
      _index.json          ← Quick lookup: [{timestamp, score, frameworks}]
      20260418_121037_AM/
        postureiq-results.json
      20260422_023002_PM/
        postureiq-results.json
```

The `_index.json` file provides fast enumeration without listing all blobs.

### Delta Analysis

When comparing two runs, the system:

1. Loads current and previous `assessment-results.json`
2. Keys each finding by `control_id|resource|check` (deterministic)
3. Computes:
   - **Score change**: +3.5% (improving) or -2.1% (declining)
   - **New findings**: Controls that were compliant before and are not now
   - **Resolved findings**: Controls that were non-compliant and are now fixed
   - **Status changes**: Controls that changed severity or status
4. Generates a delta report section in Markdown

### History Query Options

The `query_assessment_history` tool supports 4 actions:

| Action | What It Does |
|--------|-------------|
| `list` | Shows a table of recent runs (timestamp, score, findings, frameworks) |
| `trend` | Score trend over the last N runs with direction (improving/declining/stable) |
| `detail` | Full summary for a specific historical timestamp |
| `compare` | Side-by-side comparison of current vs. historical run |

---

## The Report Download Table

When an assessment completes, the chat interface displays a structured report table:

```
┌─────────────┬────────┬────────┬─────────┬─────────┐
│ Framework   │  HTML  │  PDF   │  Excel  │  JSON   │
├─────────────┼────────┼────────┼─────────┼─────────┤
│ FedRAMP     │  📄 ↓  │  📄 ↓  │  📊 ↓   │  📋 ↓   │
│ CIS         │  📄 ↓  │  📄 ↓  │  📊 ↓   │  📋 ↓   │
│ NIST 800-53 │  📄 ↓  │  📄 ↓  │  📊 ↓   │  📋 ↓   │
├─────────────┼────────┴────────┴─────────┴─────────┤
│ Shared      │ Data Exports · Evidence · SARIF ·   │
│             │ Drift Report · Remediation          │
├─────────────┼─────────────────────────────────────┤
│ Bundle      │ 📦 Download All (ZIP)                │
└─────────────┴─────────────────────────────────────┘
```

This table is embedded in the agent's response as a `<!--REPORT_TABLE:{json}-->` HTML comment, parsed by the frontend JavaScript, and rendered as an interactive download grid.

---

## Custom Reports

The `generate_custom_report` tool allows building focused reports on specific topics:

```
User: "Generate a custom report on MFA enforcement across all frameworks"

Agent:
  1. Extracts MFA-related findings from session state
  2. Filters by topic keywords and optional severity filter
  3. Builds HTML report with findings table
  4. Builds Excel report with findings + summary sheets
  5. Uploads to blob storage
  6. Returns download links
```

---

**Next:** [Manual Setup Guide →](04-manual-setup-guide.md)
