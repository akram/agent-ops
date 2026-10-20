#!/bin/bash
set -uo pipefail

KC_URL="${KEYCLOAK_URL:?KEYCLOAK_URL is required}"
KC_ADMIN_USER="${KEYCLOAK_ADMIN_USER:?KEYCLOAK_ADMIN_USER is required}"
KC_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:?KEYCLOAK_ADMIN_PASS is required}"
REALM="${KEYCLOAK_REALM:-openshell}"

get_token() {
  curl -sk --max-time 10 "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=$KC_ADMIN_USER" -d "password=$KC_ADMIN_PASS" | jq -r '.access_token'
}

kc() {
  local method="$1" path="$2"; shift 2
  curl -sk --max-time 10 -X "$method" "$KC_URL/admin/realms${path}" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$@"
}

TOKEN=$(get_token)

RM_UUID=$(kc GET "/$REALM/clients?clientId=realm-management" | jq -r '.[0].id')
echo "realm-management: $RM_UUID"

ALL_CLIENTS=$(kc GET "/$REALM/clients?max=50" | jq '[.[] | select(.clientAuthenticatorType=="federated-jwt")]')
ALL_UUIDS=$(echo "$ALL_CLIENTS" | jq '[.[].id]')
echo "Federated-jwt clients: $(echo "$ALL_CLIENTS" | jq length)"

# Pass 1: Enable FGAP on all clients
for UUID in $(echo "$ALL_CLIENTS" | jq -r '.[].id'); do
  TOKEN=$(get_token)
  NAME=$(kc GET "/$REALM/clients/$UUID" | jq -r '.clientId')
  echo "Pass 1: Enable FGAP on ${NAME:0:60}"
  kc PUT "/$REALM/clients/$UUID/management/permissions" -d '{"enabled": true}' > /dev/null 2>&1
done

# Get token-exchange scope
TOKEN=$(get_token)
TX_SCOPE_ID=$(kc GET "/$REALM/clients/$RM_UUID/authz/resource-server/scope?name=token-exchange" | jq -r '.[0].id // empty')
echo "TX scope: $TX_SCOPE_ID"

if [ -z "$TX_SCOPE_ID" ]; then
  echo "ERROR: token-exchange scope not found. Ensure admin-fine-grained-authz:v1 is enabled."
  exit 1
fi

# Pass 2: Create FGAP policies
for UUID in $(echo "$ALL_CLIENTS" | jq -r '.[].id'); do
  TOKEN=$(get_token)
  NAME=$(kc GET "/$REALM/clients/$UUID" | jq -r '.clientId')
  echo "Pass 2: FGAP for ${NAME:0:60}"

  MGMT_INFO=$(kc GET "/$REALM/clients/$UUID/management/permissions")
  TX_PERM_ID=$(echo "$MGMT_INFO" | jq -r '.scopePermissions["token-exchange"] // empty')
  RESOURCE_ID=$(echo "$MGMT_INFO" | jq -r '.resource // empty')

  if [ -z "$TX_PERM_ID" ]; then
    echo "  SKIP - no token-exchange permission"
    continue
  fi

  POLICY_NAME="all-exchange-${UUID:0:8}"
  POLICY_ID=$(kc POST "/$REALM/clients/$RM_UUID/authz/resource-server/policy/client" \
    -d "{\"name\":\"$POLICY_NAME\",\"type\":\"client\",\"logic\":\"POSITIVE\",\"decisionStrategy\":\"UNANIMOUS\",\"clients\":$ALL_UUIDS}" 2>/dev/null | jq -r '.id // empty')

  if [ -z "$POLICY_ID" ] || [ "$POLICY_ID" = "null" ]; then
    POLICY_ID=$(kc GET "/$REALM/clients/$RM_UUID/authz/resource-server/policy?name=$POLICY_NAME" | jq -r '.[0].id // empty')
    echo "  Policy exists: $POLICY_ID"
  else
    echo "  Policy created: $POLICY_ID"
  fi

  if [ -n "$POLICY_ID" ] && [ "$POLICY_ID" != "null" ]; then
    kc PUT "/$REALM/clients/$RM_UUID/authz/resource-server/permission/scope/$TX_PERM_ID" \
      -d "{\"id\":\"$TX_PERM_ID\",\"name\":\"token-exchange.permission.client.$UUID\",\"type\":\"scope\",\"logic\":\"POSITIVE\",\"decisionStrategy\":\"UNANIMOUS\",\"resources\":[\"$RESOURCE_ID\"],\"scopes\":[\"$TX_SCOPE_ID\"],\"policies\":[\"$POLICY_ID\"]}" > /dev/null 2>&1
    echo "  Linked"
  fi
done

echo "=== FGAP configuration complete ==="
