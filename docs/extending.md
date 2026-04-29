# Extending PostureIQ

> Guide for adding custom compliance frameworks, evaluators, collectors, and report formats.

## Extension Points

PostureIQ is designed to be extended in four areas:

| Extension Type | What You Add | Where |
|----------------|-------------|-------|
| **Compliance Framework** | New control mappings (e.g., custom enterprise standard) | `app/frameworks/` |
| **Evaluator Domain** | New evaluation checks for a security domain | `app/evaluators/` |
| **Collector** | New evidence source from Azure, Entra, or third-party API | `app/collectors/azure/` or `app/collectors/entra/` |
| **Report Format** | New output format or report template | `app/reports/` |

## Adding a Custom Framework

### 1. Create a mapping file

Create a JSON file in `app/frameworks/` following the existing pattern:

```json
{
  "framework": "MY-STANDARD",
  "version": "1.0",
  "description": "My Custom Security Standard",
  "controls": [
    {
      "id": "MY-1.1",
      "title": "Enforce MFA for all users",
      "domain": "identity",
      "check": "check_mfa_coverage",
      "severity": "high"
    },
    {
      "id": "MY-1.2",
      "title": "Encrypt data at rest",
      "domain": "data_protection",
      "check": "check_encryption_at_rest",
      "severity": "critical"
    }
  ]
}
```

**Key fields:**
- `id` — Control identifier (must be unique within the framework)
- `domain` — Maps to one of the 10 evaluation domains
- `check` — Name of the evaluator check function to invoke
- `severity` — Default severity for findings (critical, high, medium, low, informational)

### 2. Register the framework

The framework loader auto-discovers JSON files in `app/frameworks/`. Once your mapping file is placed there, it will be available by its `framework` name.

### 3. Select it

```bash
export ENTERPRISESECURITYIQ_FRAMEWORKS="MY-STANDARD,NIST-800-53"
```

Or in the config JSON:

```json
{
  "frameworks": ["MY-STANDARD", "NIST-800-53"]
}
```

## Adding a Custom Evaluator

### 1. Create a check function

Add a new check function in the appropriate domain evaluator file. Check functions follow this pattern:

```python
def check_my_custom_check(evidence: dict, config: dict) -> list[Finding]:
    """Check description — used in reports."""
    findings = []
    
    resources = evidence.get("MyEvidenceType", [])
    for resource in resources:
        compliant = resource.get("SomeProperty", False)
        findings.append(Finding(
            control_id="MY-1.3",
            status="Compliant" if compliant else "NonCompliant",
            severity="high",
            resource_id=resource.get("Id", ""),
            resource_name=resource.get("Name", ""),
            detail=f"Resource {'meets' if compliant else 'does not meet'} requirement",
            remediation="Enable SomeProperty on the resource"
        ))
    
    return findings
```

### 2. Map it to your framework

Add an entry in your framework mapping file referencing `check_my_custom_check`.

## Adding a Custom Collector

### 1. Create a collector module

Use the `@register_collector` decorator for auto-discovery:

```python
from app.collectors.registry import register_collector
from app.collectors.base import BaseCollector

@register_collector("my_custom_data")
class MyCustomCollector(BaseCollector):
    """Collect custom data from an Azure resource."""
    
    evidence_types = ["MyEvidenceType"]
    
    async def collect(self, credential, subscriptions, config):
        results = []
        for sub in subscriptions:
            # Call Azure SDK or REST API (read-only only)
            data = await self._list_resources(credential, sub)
            results.extend(self.normalize(data))
        return {"MyEvidenceType": results}
```

**Key requirements:**
- Use the `@register_collector` decorator with a unique name
- Extend `BaseCollector` to inherit retry, pagination, and error handling
- Define `evidence_types` for the evidence catalog
- Only make read-only API calls
- Return normalized evidence dicts with PascalCase keys

### 2. The collector is auto-discovered

The registry scans `app/collectors/azure/` and `app/collectors/entra/` at startup. No manual registration needed.

## Adding a Custom Report Format

### 1. Create a report module

```python
from app.reports.base import BaseReportGenerator

class MyFormatReport(BaseReportGenerator):
    """Generate reports in my custom format."""
    
    format_name = "myformat"
    file_extension = ".myf"
    
    def generate(self, assessment_result, output_dir, config):
        content = self.format_findings(assessment_result)
        output_path = self.write_output(content, output_dir)
        return output_path
```

### 2. Register the format

Add your format to the report factory so it can be selected via config:

```json
{
  "outputFormats": ["json", "html", "myformat"]
}
```

## Evaluation Rules Reference

### Check Function Naming

Check functions follow the pattern `check_<domain>_<what>`:
- `check_mfa_coverage` — Identity domain, MFA coverage
- `check_encryption_at_rest` — Data protection domain, encryption

### Severity Levels

| Level | Weight | Description |
|-------|--------|-------------|
| Critical | 1.0 | Immediate exploitation risk, data breach potential |
| High | 0.8 | Significant security gap, exploit requires limited effort |
| Medium | 0.5 | Notable weakness, mitigated by other controls |
| Low | 0.2 | Minor improvement opportunity |
| Informational | 0.0 | Best practice recommendation, no direct risk |

### Finding Statuses

| Status | Meaning |
|--------|---------|
| Compliant | Resource meets the control requirement |
| NonCompliant | Resource fails the control requirement |
| NotApplicable | Control does not apply to this resource type |
| Error | Evidence collection or evaluation error |

## Evaluator Plugin System

PostureIQ includes a plugin loader that can discover evaluator plugins from external packages. Plugins are loaded from the `ENTERPRISESECURITYIQ_PLUGIN_DIR` path if set.

## Testing Custom Extensions

Run the determinism check after adding extensions to verify consistent output:

```bash
python run_assessment_determinism_check.py --tenant <id>
```

This runs the assessment twice with identical inputs and verifies byte-identical output.
