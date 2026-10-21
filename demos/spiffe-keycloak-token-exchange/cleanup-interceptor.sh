#!/bin/bash
set -uo pipefail

KC_URL="${KEYCLOAK_URL:-https://sso.apps.cluster-tlszf.dyn.redhatworkshops.io}"
KC_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-temp-admin}"
KC_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:-87fcb0d555be466f9cbbfed292060b4f}"
REALM="openshell"

ADMIN_TOKEN=$(curl -sk --max-time 10 -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=$KC_ADMIN_USER" -d "password=$KC_ADMIN_PASS" | jq -r '.access_token')

echo "=== Cleaning up Keycloak state for fresh interceptor demo ==="

# 1. Delete all FGAP policies on realm-management
RM_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
for POLICY_ID in $(curl -sk "$KC_URL/admin/realms/$REALM/clients/$RM_UUID/authz/resource-server/policy?max=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.name | test("exchange|sandbox|gateway")) | .id'); do
  curl -sk -X DELETE "$KC_URL/admin/realms/$REALM/clients/$RM_UUID/authz/resource-server/policy/$POLICY_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null
done
echo "  FGAP policies deleted"

# 2. Disable management permissions on all federated-jwt clients + model-api
for CLIENT_UUID in $(curl -sk "$KC_URL/admin/realms/$REALM/clients?max=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.clientAuthenticatorType=="federated-jwt") | .id'); do
  curl -sk -X PUT "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/management/permissions" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d '{"enabled": false}' 2>/dev/null
done
MODEL_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=model-api" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
curl -sk -X PUT "$KC_URL/admin/realms/$REALM/clients/$MODEL_UUID/management/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": false}' 2>/dev/null
echo "  Management permissions disabled"

# 3. Delete all sandbox federated-jwt clients (keep gateway + openshell.os-supervisor)
for CLIENT_UUID in $(curl -sk "$KC_URL/admin/realms/$REALM/clients?max=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.clientAuthenticatorType=="federated-jwt" and (.clientId | test("sandbox/[0-9a-f]"))) | .id'); do
  NAME=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.clientId[0:60]')
  curl -sk -X DELETE "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
  echo "  Deleted client: $NAME"
done

# 4. Remove realm-management roles from keycloak-registrar SA
KC_REG_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=keycloak-registrar" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id // empty')
if [ -n "$KC_REG_UUID" ]; then
  SA_USER=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$KC_REG_UUID/service-account-user" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.id')
  ROLES=$(curl -sk "$KC_URL/admin/realms/$REALM/users/$SA_USER/role-mappings/clients/$RM_UUID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  if [ "$(echo "$ROLES" | jq length)" -gt 0 ]; then
    curl -sk -X DELETE "$KC_URL/admin/realms/$REALM/users/$SA_USER/role-mappings/clients/$RM_UUID" \
      -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
      -d "$ROLES" 2>/dev/null
    echo "  Removed all realm-management roles from keycloak-registrar SA"
  fi
fi

# 5. Delete existing sandbox in OpenShell
GW="${OPENSHELL_GATEWAY:-http://127.0.0.1:8099}"
OPENSHELL_CLI="${OPENSHELL_CLI:-/tmp/openshell-cli/openshell}"
GATEWAY_NAME="${GATEWAY_NAME:-saw-cluster}"
if nc -z 127.0.0.1 8099 2>/dev/null; then
  "$OPENSHELL_CLI" --gateway "$GATEWAY_NAME" --gateway-endpoint "$GW" sandbox delete model-demo 2>/dev/null && echo "  Deleted sandbox model-demo" || true
fi

echo "=== Cleanup complete ==="
