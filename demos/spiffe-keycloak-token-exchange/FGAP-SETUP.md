# FGAP v1 Setup Guide

When RHBK 26.6+ has the `admin-fine-grained-authz:v1` feature enabled, token exchange requires explicit FGAP permissions. This document covers what the interceptor handles automatically and what must be configured once manually.

## What the interceptor configures automatically

For each new sandbox, the interceptor:
1. Enables management permissions on the audience client (e.g. `model-api`)
2. Creates a client policy for the sandbox's SPIFFE ID
3. Links the policy to the `token-exchange` scope permission on the audience

The audience clients are derived from `DEFAULT_CLIENT_SCOPES` (no separate configuration needed).

This requires the interceptor's service account to have the `manage-authorization` role on `realm-management`, in addition to the existing `manage-clients`, `view-clients`, and `query-clients` roles.

## Adding the manage-authorization role

The interceptor's Keycloak service account needs `manage-authorization` on `realm-management`. This is a one-time setup per realm:

```bash
KC_URL="<your keycloak URL>"
REALM="openshell"

# Get admin token
ADMIN_TOKEN=$(curl -sk -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=<admin>" -d "password=<password>" | jq -r '.access_token')

# Find the interceptor client and its service account
CLIENT_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=keycloak-registrar" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

SA_USER=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/service-account-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.id')

# Find realm-management client
RM_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

# Find the manage-authorization role ID
ROLE_ID=$(curl -sk "$KC_URL/admin/realms/$REALM/users/$SA_USER/role-mappings/clients/$RM_UUID/available" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.name == "manage-authorization") | .id')

# Assign the role
curl -sk -X POST "$KC_URL/admin/realms/$REALM/users/$SA_USER/role-mappings/clients/$RM_UUID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[{\"id\":\"$ROLE_ID\",\"name\":\"manage-authorization\"}]"
```

## Gateway FGAP permissions

The interceptor now automatically configures FGAP permissions for the gateway client alongside each sandbox. No manual configuration is needed.

The `configure-fgap.sh` script is retained as a fallback for environments where the interceptor does not have the `manage-authorization` role, or for initial bootstrapping of pre-existing clients.

## Summary of required roles

| Client | Required realm-management roles |
|--------|-------------------------------|
| keycloak-registrar (interceptor SA) | manage-clients, view-clients, query-clients, **manage-authorization** |
