---
description: "Scaffold a new IQ assessment platform from a domain definition. Use when: create new platform, scaffold project, generate agent repo, new IQ tool, build assessment tool."
agent: "agent"
tools: ["run_in_terminal", "create_file", "read_file", "replace_string_in_file"]
---
You are helping scaffold a new IQ assessment platform using **IQForge**.

Read the repo instructions at [copilot-instructions](.github/copilot-instructions.md) for the full YAML schema and generation workflow.

## Your Task

Guide the user through creating a new platform by gathering requirements conversationally:

### Step 1 — Gather Requirements
Ask the user (use the ask-questions tool if available, otherwise ask in chat):

1. **Project name** — What should the platform be called? (e.g., "FinOpsIQ", "ComplianceIQ")
2. **Domain** — What domain does it assess? (security, finops, devsecops, compliance, custom)
3. **Data sources** — What APIs will collectors pull from?
   - Azure Resource Manager APIs (which services?)
   - Microsoft Graph APIs (users, groups, policies?)
   - Custom/external sources?
4. **Framework** — What standard/framework to assess against? (NIST, CIS, FinOps Foundation, custom)
5. **Controls** — List specific controls, or say "generate defaults for [framework]"
6. **Output location** — Where to generate the project (absolute path)

### Step 2 — Generate YAML Config
Based on the answers, create a YAML domain-definition file at `configs/<project-name>.yaml`.
Follow the schema in the copilot-instructions. Reference examples at `examples/` for structure.

### Step 3 — Validate
Run in terminal:
```
python iqforge.py validate --config configs/<project-name>.yaml
```
Fix any validation errors before proceeding.

### Step 4 — Scaffold
Run in terminal:
```
python iqforge.py create --config configs/<project-name>.yaml --output <user-specified-path> --force
```

### Step 5 — Summary
After scaffolding, summarize:
- Total files and directories created
- List the collector stubs that need implementation
- List the evaluator stubs that need implementation
- Note that `Infra/deploy.ps1` needs Azure config (AI Foundry, Entra app)
- Confirm everything else works out of the box
