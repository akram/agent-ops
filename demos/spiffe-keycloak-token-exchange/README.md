# SPIFFE + Keycloak Token Exchange Demo

End-to-end demo of workload identity with user delegation on OpenShift, using SPIFFE/SPIRE + Red Hat Build of Keycloak + OpenShell.

## Recordings

**6 security scenarios** (token exchange flow, rejections, multi-user):
[![asciicast](https://asciinema.org/a/tETTOnFHnUFyYLSL.svg)](https://asciinema.org/a/tETTOnFHnUFyYLSL)

**Automated FGAP** (zero-config: sandbox create → interceptor → FGAP → exchange):
[![asciicast](https://asciinema.org/a/aXw9UG0ncOphEYwA.svg)](https://asciinema.org/a/aXw9UG0ncOphEYwA)

## What it demonstrates

A two-stage RFC 8693 token exchange flow:

1. **Gateway** exchanges Alice's OIDC token + gateway JWT-SVID at Keycloak, producing an intermediate token
2. **Supervisor** exchanges the intermediate token + sandbox JWT-SVID at Keycloak, producing a final token containing:
   - `sub` = the user (Alice)
   - `azp` = the sandbox SPIFFE ID (cryptographic workload identity)
   - `aud` = the target service (model-api)

The sandbox process never sees any token; the supervisor injects `Authorization: Bearer` transparently.

## 6 security scenarios

| # | Scenario | Result |
|---|----------|--------|
| 1 | Sandbox + Alice | Success: sub=alice, azp=sandbox SPIFFE ID |
| 2 | Direct call without sandbox | 401: no token injected |
| 3 | Valid SPIFFE pod, not a registered sandbox | Client rejected by Keycloak |
| 4 | Sandbox without FGAP permission | Exchange denied |
| 5 | Disabled user (Bob) | No token issued |
| 6 | Sandbox + Claire (different user) | Success: sub=claire, same sandbox |

## Stack

- OpenShift 4.22
- ZTWIM (Zero Trust Workload Identity Manager) / SPIRE v1.1.2
- Red Hat Build of Keycloak (RHBK) 26.6.7 with `spiffe:v1` and `admin-fine-grained-authz:v1`
- OpenShell with `fix/token-exchange-client-id` patch

## Files

| File | Description |
|------|-------------|
| `record.sh` | Asciinema recording script: 6 security scenarios (160 cols, ~95s) |
| `record-automated-fgap.sh` | Asciinema recording script: automated FGAP demo (160 cols, ~120s) |
| `model-api.js` | Mock model API (Node.js) that validates bearer tokens and returns identity claims |
| `model-api-deployment.yaml` | Kubernetes deployment for the mock model API |
| `provider-profile-keycloak.yaml` | OpenShell provider profile for SPIFFE + Keycloak token exchange |
| `keycloak-registrar-deployment.yaml` | Interceptor deployment in the openshell namespace |
| `configure-fgap.sh` | FGAP v1 permission configuration (workaround until interceptor PR is merged) |

## Prerequisites

1. An OpenShift cluster with ZTWIM operator installed
2. RHBK 26.6+ with `spiffe:v1` feature enabled
3. OpenShell deployed with the keycloak-registrar interceptor
4. ClusterSPIFFEIDs with `className: zero-trust-workload-identity-manager-spire`

## Setup

```bash
# Deploy mock model API
oc apply -f model-api-deployment.yaml

# Deploy keycloak-registrar interceptor
oc apply -f keycloak-registrar-deployment.yaml

# Create the OpenShell provider
openshell provider create \
  --name keycloak-model-demo \
  --type spiffe-keycloak-model-api

# Create a sandbox with curl and the provider
openshell sandbox create \
  --name model-demo \
  --provider keycloak-model-demo \
  --from image-registry.openshift-image-registry.svc:5000/openshell-images/sandbox-with-curl:latest

# Configure FGAP permissions (until interceptor PR #1 is merged)
bash configure-fgap.sh

# Record the demo
asciinema rec --cols 160 --rows 50 demo.cast -c "bash record.sh"
```

## Key findings

- OpenShell gateway must send `client_id` in token exchange requests (patched on `fix/token-exchange-client-id`)
- Keycloak federated-jwt clients require `jwt.credential.issuer` and `jwt.credential.sub` attributes
- FGAP v1 permissions must be configured explicitly; `standard.token.exchange.enabled` is ignored when FGAP is active
- ClusterSPIFFEIDs require `className` for ZTWIM to process them
- FGAP v2 is broken in RHBK 26.6; must use v1
