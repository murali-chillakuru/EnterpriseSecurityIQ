# Configuration

> Environment variables, JSON config file, thresholds, suppressions, and troubleshooting.

## Configuration Sources

PostureIQ loads configuration from two sources (environment variables take precedence):

1. **Environment variables** — prefixed with `ENTERPRISESECURITYIQ_`
2. **JSON config file** — pointed to by `ENTERPRISESECURITYIQ_CONFIG`

## Environment Variables

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `AZURE_TENANT_ID` | — | Target Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | — | Filter to a specific subscription |
| `AZURE_CLIENT_ID` | — | Service principal client ID (SP mode) |
| `AZURE_CLIENT_SECRET` | — | Service principal secret (SP mode) |
| `ENTERPRISESECURITYIQ_CONFIG` | — | Path to JSON config file |
| `ENTERPRISESECURITYIQ_FRAMEWORKS` | All | Comma-separated framework list |
| `ENTERPRISESECURITYIQ_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `ENTERPRISESECURITYIQ_OUTPUT_DIR` | `./output` | Output directory for reports |
| `ENTERPRISESECURITYIQ_OUTPUT_FORMATS` | `json,html` | Comma-separated output formats |

### Foundry Agent Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FOUNDRY_PROJECT_ENDPOINT` | — | Foundry project endpoint URL |
| `FOUNDRY_MODEL_DEPLOYMENT_NAME` | `gpt-4.1` | Deployed model name |

### Collector Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ENTERPRISESECURITYIQ_AZURE_ENABLED` | `true` | Enable Azure ARM collectors |
| `ENTERPRISESECURITYIQ_ENTRA_ENABLED` | `true` | Enable Entra ID (Graph) collectors |
| `ENTERPRISESECURITYIQ_AZURE_BATCH_SIZE` | `4` | Concurrent Azure collector limit |
| `ENTERPRISESECURITYIQ_ENTRA_BATCH_SIZE` | `3` | Concurrent Entra collector limit |
| `ENTERPRISESECURITYIQ_COLLECTOR_TIMEOUT` | `300` | Per-collector timeout in seconds |
| `ENTERPRISESECURITYIQ_USER_SAMPLE_LIMIT` | `0` | Max users to sample (0 = all) |
| `ENTERPRISESECURITYIQ_CHECKPOINT_ENABLED` | `true` | Enable checkpoint/resume |

## JSON Config File

Create a JSON config file and point to it:

```bash
export ENTERPRISESECURITYIQ_CONFIG="config/enterprisesecurityiq.config.json"
```

Example configuration:

```json
{
  "$schema": "config.schema.json",
  "name": "PostureIQ Assessment",
  "frameworks": ["FedRAMP", "CIS", "NIST-800-53"],
  "logLevel": "INFO",
  "outputFormats": ["json", "html", "md"],
  "outputDir": "./output",
  "checkpointEnabled": true,
  "auth": {
    "tenantId": "your-tenant-id",
    "authMode": "auto",
    "subscriptionFilter": []
  },
  "collectors": {
    "azureEnabled": true,
    "entraEnabled": true,
    "azureBatchSize": 4,
    "entraBatchSize": 3,
    "collectorTimeout": 300,
    "userSampleLimit": 0
  }
}
```

A JSON Schema is available at `config/config.schema.json` for editor validation.

## Framework Selection

Specify frameworks by their short names:

| Short Name | Framework |
|-----------|-----------|
| `NIST-800-53` | NIST 800-53 Rev 5 |
| `FedRAMP` | FedRAMP Moderate |
| `CIS` | CIS Azure Benchmark v2.0 |
| `MCSB` | Microsoft Cloud Security Benchmark |
| `PCI-DSS` | PCI DSS v4.0 |
| `ISO-27001` | ISO 27001:2022 |
| `SOC2` | SOC 2 Type II |
| `HIPAA` | HIPAA Security Rule |
| `NIST-CSF` | NIST Cybersecurity Framework |
| `CSA-CCM` | CSA Cloud Controls Matrix |
| `GDPR` | GDPR |

## Suppressions

Suppress specific findings to exclude them from reports (e.g., accepted risks, compensating controls):

Suppressions are defined as rules that match findings by control ID, resource, or domain. Each suppression includes:

- **Rule ID** — unique identifier
- **Match criteria** — control ID pattern, resource name, or domain
- **Justification** — reason for suppression (required for audit trail)
- **Expiry** — optional date when the suppression expires

Suppressed findings are still collected and evaluated but are marked as suppressed in reports with the justification attached.

## Authentication Modes

| Mode | When Used | Configuration |
|------|-----------|---------------|
| **Auto** | Default | Uses `DefaultAzureCredential` chain — picks up `az login`, managed identity, or env vars |
| **ServicePrincipal** | CI/CD, automation | Set `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` |
| **ManagedIdentity** | Container Apps | Assign system or user-assigned managed identity to the container |

The preflight check verifies:
1. ARM access (list subscriptions)
2. Graph connectivity (tenant info)
3. Entra directory role (read permissions)

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| `DefaultAzureCredential failed` | Run `az login` or set service principal env vars |
| `Insufficient privileges` | Ensure Reader + Security Reader roles and Graph read permissions |
| `Module not found` | Run `pip install -r AIAgent/requirements.txt` |
| `Partial collection` | Orchestrator continues on partial failures; check logs for details |
| `Key Vault access denied` | Ensure Key Vault RBAC or access policy grants List permissions |
| `Collector timeout` | Increase `ENTERPRISESECURITYIQ_COLLECTOR_TIMEOUT` (default 300s) |
| `Rate limiting` | Reduce batch sizes: `ENTERPRISESECURITYIQ_AZURE_BATCH_SIZE` |
| `Large tenant slow` | Set `ENTERPRISESECURITYIQ_USER_SAMPLE_LIMIT` to reduce user enumeration |
| `Checkpoint stale data` | Delete the checkpoint file in the output directory and re-run |

## Report Integrity Verification

Every report includes a SHA-256 hash. Verify with:

```powershell
Get-FileHash "output\<timestamp>\compliance-report.html" -Algorithm SHA256
```

If the computed hash matches the hash in the report, the report is untampered.
