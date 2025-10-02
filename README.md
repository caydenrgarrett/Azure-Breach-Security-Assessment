# Azure Assumed Breach & Security Assessment <br>

![image alt](https://learn.microsoft.com/en-us/azure/well-architected/security/images/incident-response/incident-response.png)

This document operationalizes an assumed breach assessment in an Azure tenant. It translates the scenario into reproducible steps with explicit inputs and expected outputs to help you validate access controls, secrets management, logging, RBAC, and MFA policies.

## Scope & Objectives
- Validate that an attacker with initial foothold is contained and detected
- Assess exposure of secrets (Azure Key Vault) and identity controls (Microsoft Entra ID)
- Identify RBAC misconfigurations and excessive privileges
- Enforce MFA and least-privilege access; verify effectiveness post-hardening

## Prerequisites
- Azure subscription with contributor access to a non-production tenant
- Microsoft Entra ID (formerly Azure AD) admin for test identities/policies
- Azure CLI installed and logged in (`az login`)
- Optional: Microsoft Defender for Cloud, Microsoft Sentinel, Log Analytics workspace

## Inputs (provide before running)
- TENANT_ID: <your-tenant-id>
- SUBSCRIPTION_ID: <your-subscription-id>
- RG_NAME: <assessment-resource-group>
- LOCATION: <e.g., eastus>
- KV_NAME: <globally-unique-keyvault-name>
- TEST_USER_UPN: <test-user@yourdomain.com>
- TEST_APP_NAME: <test-sp-app-name>
- LOG_WS_NAME: <log-analytics-workspace-name>

Set environment variables for convenience:

```bash
export TENANT_ID="..."
export SUBSCRIPTION_ID="..."
export RG_NAME="ab-assess-rg"
export LOCATION="eastus"
export KV_NAME="ab-kv-$(openssl rand -hex 3)"
export TEST_USER_UPN="attacker.sim@testdomain.onmicrosoft.com"
export TEST_APP_NAME="ab-assess-app"
export LOG_WS_NAME="ab-assess-logs"
```

## High-Level Workflow
1. Prepare sandbox and seed realistic assets
2. Simulate attacker foothold (test user/SP) and enumerate
3. Attempt lateral movement and data access (Key Vault, storage, mgmt plane)
4. Investigate activity using logs and security tools
5. Identify RBAC weaknesses and excessive privileges
6. Implement MFA and RBAC hardening
7. Re-test to confirm controls block the same attack paths

## Step 1 — Prepare Environment
Inputs: SUBSCRIPTION_ID, RG_NAME, LOCATION, KV_NAME, LOG_WS_NAME

```bash
az account set --subscription "$SUBSCRIPTION_ID"
az group create -n "$RG_NAME" -l "$LOCATION"
az monitor log-analytics workspace create -g "$RG_NAME" -n "$LOG_WS_NAME"
az keyvault create -g "$RG_NAME" -n "$KV_NAME" -l "$LOCATION" --enable-rbac-authorization true
# Seed a secret to simulate sensitive data
az keyvault secret set --vault-name "$KV_NAME" --name "DbPassword" --value "SuperSecretP@ssw0rd!" >/dev/null
```

Expected outputs:
- Resource group and Log Analytics workspace created
- Key Vault exists with `DbPassword` secret

## Step 2 — Create Assumed Breach Principals
Inputs: TEST_USER_UPN, TEST_APP_NAME

```bash
# Create a low-privilege user to simulate a compromised identity
az ad user create \
  --display-name "Attacker Sim" \
  --user-principal-name "$TEST_USER_UPN" \
  --password "TempP@ssw0rd123!" \
  --force-change-password-next-sign-in false

# Create a service principal to simulate an app compromise
SP_JSON=$(az ad sp create-for-rbac -n "$TEST_APP_NAME" --skip-assignment)
echo "$SP_JSON" | jq -r '.appId, .tenant, .password' | paste - - - | awk '{print "APP_ID=" $1 " TENANT=" $2 " APP_SECRET=" $3}'
```

Expected outputs:
- Test user created in Entra ID
- Service principal created and credentials displayed (store securely for test)

## Step 3 — Minimal RBAC Grant (Baseline Misconfig)
Inputs: RG_NAME, TEST_APP_NAME

```bash
# Intentionally misconfigure: grant Reader at resource group to simulate common mistake
SP_OBJ_ID=$(az ad sp list --display-name "$TEST_APP_NAME" --query "[0].id" -o tsv)
az role assignment create \
  --assignee-object-id "$SP_OBJ_ID" \
  --assignee-principal-type ServicePrincipal \
  --role Reader \
  --resource-group "$RG_NAME"
```

Expected outputs:
- Reader role assignment applied at `RG_NAME`
- Note: Reader should NOT allow Key Vault secret read with RBAC authorization; this validates least privilege

## Step 4 — Simulate Attacker Enumeration
Inputs: APP_ID, APP_SECRET, TENANT_ID

```bash
# Login as the compromised app
az login --service-principal -u "$APP_ID" -p "$APP_SECRET" --tenant "$TENANT_ID" --output none

# Enumerate subscriptions and accessible resources
az account show -o table
az resource list -o table | head -n 10

# Attempt to list Key Vault secrets (should fail with Reader)
az keyvault secret list --vault-name "$KV_NAME" -o table || echo "Expected failure (insufficient privileges)"
```

Expected outputs:
- App can see resources metadata due to Reader
- Secret listing fails with authorization error (expected)

## Step 5 — Assess Secrets Exposure Scenarios
Inputs: KV_NAME

Test 5.1 — Direct Secret Read (should fail)
```bash
az keyvault secret show --vault-name "$KV_NAME" --name "DbPassword" -o tsv || echo "Expected failure"
```

Expected outputs:
- Authorization failure confirms RBAC is blocking reads

Test 5.2 — Mis-scoped Role (simulate common misconfig)
```bash
# Grant too-broad role to the app (Key Vault Secrets User) to simulate exposure
az role assignment create \
  --assignee "$APP_ID" \
  --role "Key Vault Secrets User" \
  --scope $(az keyvault show -n "$KV_NAME" --query id -o tsv)

# Retry secret read (should now succeed — demonstrating risk)
az keyvault secret show --vault-name "$KV_NAME" --name "DbPassword" --query value -o tsv
```

Expected outputs:
- Secret value returned, proving misconfiguration leads to data exposure

## Step 6 — Investigate Activity (Logs & Security Tools)
Inputs: LOG_WS_NAME, SUBSCRIPTION_ID

Configure diagnostic settings (if not already via policy):
```bash
# Enable Key Vault diagnostics to Log Analytics
KV_ID=$(az keyvault show -n "$KV_NAME" --query id -o tsv)
WS_ID=$(az monitor log-analytics workspace show -g "$RG_NAME" -n "$LOG_WS_NAME" --query id -o tsv)
az monitor diagnostic-settings create \
  --name "send-to-law" \
  --resource "$KV_ID" \
  --workspace "$WS_ID" \
  --logs '[{"category":"AuditEvent","enabled":true}]'
```

Query examples (KQL) to validate detections:
```text
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where Category == "AuditEvent"
| where OperationName has "SecretGet"
| project TimeGenerated, ResultSignature, CallerIPAddress, Identity, OperationName
| sort by TimeGenerated desc
```

Expected outputs:
- Audit logs showing secret read attempts with identity and result
- Use Defender for Cloud / Sentinel to visualize alerts if enabled

## Step 7 — Identify RBAC Weaknesses
Inputs: SUBSCRIPTION_ID, RG_NAME

```bash
# List role assignments at RG scope
az role assignment list --resource-group "$RG_NAME" -o table | head -n 20

# Identify high-privilege roles and broad scopes
az role assignment list --all --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator'].[principalName,roleDefinitionName,scope]" -o table
```

Expected outputs:
- Inventory of assignments highlighting excessive privileges or non-justified broad scopes

## Step 8 — Implement Security Controls (MFA & RBAC Hardening)
Inputs: TEST_USER_UPN, KV_NAME, APP_ID

RBAC Hardening:
```bash
# Remove broad assignment
az role assignment delete --assignee "$APP_ID" --role "Key Vault Secrets User" --scope $(az keyvault show -n "$KV_NAME" --query id -o tsv)

# Grant least-privilege only where necessary (example: none for this app)
```

MFA Enforcement (policy guidance):
- Create a Conditional Access policy requiring MFA for: all users except break-glass, all cloud apps, exclude service principals
- Enforce phishing-resistant MFA where possible (FIDO2, Certificate-based)

Expected outputs:
- Secret read attempts by the app now fail
- User interactive sign-ins prompt for MFA and are blocked without compliance

## Step 9 — Re-Test Controls
Inputs: APP_ID, APP_SECRET, TENANT_ID, KV_NAME

```bash
# Re-login as app and retry secret access (should fail)
az login --service-principal -u "$APP_ID" -p "$APP_SECRET" --tenant "$TENANT_ID" --output none
az keyvault secret show --vault-name "$KV_NAME" --name "DbPassword" -o tsv || echo "Access blocked as expected"
```

Expected outputs:
- Access blocked message; audit logs show denied attempts

## Reporting Template (fill during/after assessment)
- Executive Summary: one-paragraph overview of risk and outcome
- Initial Foothold Vector(s): list and likelihood
- Key Findings:
  - Excessive role assignments (who/where)
  - Secrets exposure pathways (which vaults/secrets)
  - Logging/visibility gaps
- Implemented Controls:
  - RBAC changes, CA/MFA policies, diagnostics
- Validation Results:
  - Before vs after attack path outcomes
- Recommendations & Next Steps:
  - Policy as Code, PIM, Just-In-Time, break-glass, automation

## Cleanup (avoid lingering risk/cost)
Inputs: RG_NAME, TEST_USER_UPN, TEST_APP_NAME

```bash
# Remove test resources and identities
az group delete -n "$RG_NAME" --yes --no-wait || true
az ad sp delete --id $(az ad sp list --display-name "$TEST_APP_NAME" --query "[0].appId" -o tsv) || true
az ad user delete --id "$TEST_USER_UPN" || true
```

Expected outputs:
- Resource group scheduled for deletion; test identities removed

## Notes & Safety
- Project was completed over the Google Cybersecurity Professional Course
- Run only in non-production tenants
- Store secrets from Step 2 in a secure location and delete after testing
- Ensure you have a break-glass account excluded from MFA/CA policies for safety
