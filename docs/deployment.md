# Deployment

> Container build, Azure Container Apps deployment, CI/CD pipelines, and infrastructure setup.

## Deployment Options

| Option | Description |
|--------|-------------|
| **Azure Container Apps** | Production deployment via ACR build + Container App revision |
| **Microsoft Foundry** | Hosted agent via container image on Foundry |
| **Local development** | Direct Python execution for testing and development |

## Container Build

PostureIQ ships as a Docker container based on `python:3.12-slim`. The image includes Playwright Chromium for PDF report generation.

### Build locally

```bash
docker build --platform linux/amd64 -t postureiq-agent -f AIAgent/Dockerfile .
```

### Build via Azure Container Registry

```bash
az acr build --registry <your-acr> --image postureiq-agent:v<version> --file AIAgent/Dockerfile .
```

## Azure Container Apps Deployment

### Prerequisites

- Azure Container Registry (ACR) with the built image
- Azure Container App environment
- Managed Identity with required permissions (see [Getting Started](getting-started.md))

### Deploy a new revision

```bash
az containerapp update \
  --name <app-name> \
  --resource-group <rg-name> \
  --image <acr-name>.azurecr.io/postureiq-agent:v<version>
```

### Environment variables

Set these on the Container App:

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Target Azure AD tenant |
| `AZURE_CLIENT_ID` | If SP | Service principal client ID |
| `AZURE_CLIENT_SECRET` | If SP | Service principal secret |
| `FOUNDRY_PROJECT_ENDPOINT` | Agent mode | Foundry project endpoint URL |
| `FOUNDRY_MODEL_DEPLOYMENT_NAME` | Agent mode | Deployed model name (default: `gpt-4.1`) |

### Health check

The container exposes a health endpoint at `/health` on port 8088.

## Microsoft Foundry Deployment

1. Build and push the container image to ACR
2. Create a hosted agent in Foundry pointing to the container image
3. The agent exposes port 8088 and uses the `responses` protocol v1
4. Configure the Foundry project endpoint and model deployment name

## Local Development

```bash
cd AIAgent
pip install -r requirements.txt
az login

# Run as agent server
python main.py  # port 8088

# Or run as API server
python -m uvicorn app.api:app --host 0.0.0.0 --port 8090
```

### Debug with AI Toolkit Inspector

In VS Code, press **F5** and select **Debug PostureIQ Agent (HTTP Server)**. This launches with `agentdev` instrumentation.

## CI/CD Integration

### GitHub Actions

PostureIQ supports CI/CD integration via SARIF output:

1. Run an assessment in CI with `--format sarif`
2. Upload the SARIF file to GitHub Code Scanning
3. Findings appear as security alerts in the repository

### Azure DevOps

1. Run an assessment as a pipeline task
2. Publish the HTML report as a pipeline artifact
3. Use webhook output to push results to Azure Boards or ServiceNow

## Container Security

- Runs as non-root user (`appuser`)
- No secrets stored in the image — all sensitive values come from environment variables or managed identity
- Health check enabled with 30-second intervals
- Playwright installed only for PDF rendering (Chromium sandbox)

## Web Dashboard

The container also serves a web dashboard at `/` for interactive access to the API endpoints. The dashboard files are bundled from the `webapp/` directory during build.
