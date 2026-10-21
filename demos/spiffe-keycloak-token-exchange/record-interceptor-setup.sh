#!/bin/bash
set -uo pipefail

KC_URL="${KEYCLOAK_URL:-https://sso.apps.cluster-tlszf.dyn.redhatworkshops.io}"
KC_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-temp-admin}"
KC_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:-87fcb0d555be466f9cbbfed292060b4f}"
REALM="openshell"

Y="\033[1;33m"; C="\033[1;36m"; G="\033[1;32m"; B="\033[1;34m"
M="\033[1;35m"; R="\033[1;31m"; W="\033[1;37m"; D="\033[0;37m"; O="\033[0m"

banner() { echo ""; echo -e "${Y}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${O}"; echo -e "${Y}  $1${O}"; echo -e "${Y}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${O}"; echo ""; sleep 2; }

kc_admin_token() {
  curl -sk --max-time 10 -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=$KC_ADMIN_USER" -d "password=$KC_ADMIN_PASS" | jq -r '.access_token'
}

# ═══════════════════════════════════════════════════════
banner "Keycloak Registrar Interceptor: Installation & Configuration"
echo -e "${D}This demo walks through the full setup of the keycloak-registrar${O}"
echo -e "${D}interceptor on OpenShift, including Keycloak service account,${O}"
echo -e "${D}RBAC permissions, image build, and deployment.${O}"
echo ""
echo -e "${W}Prerequisites:${O}"
echo -e "${D}  - OpenShift cluster with OpenShell gateway deployed${O}"
echo -e "${D}  - Red Hat Build of Keycloak (RHBK 26.6+) with a realm configured${O}"
echo -e "${D}  - admin-fine-grained-authz:v1 feature enabled on the realm${O}"
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 1: Create Keycloak service account for the interceptor"

echo -e "${D}The interceptor needs a Keycloak client with client_credentials grant${O}"
echo -e "${D}to manage sandbox clients in the realm.${O}"
echo ""
echo -e "  ${C}> curl -sk -X POST \$KC_URL/admin/realms/$REALM/clients \\${O}"
echo -e "  ${C}    -H \"Authorization: Bearer \$ADMIN_TOKEN\" \\${O}"
echo -e "  ${C}    -H \"Content-Type: application/json\" \\${O}"
echo -e "  ${C}    -d '{\"clientId\": \"keycloak-registrar\", \"enabled\": true, \"publicClient\": false,${O}"
echo -e "  ${C}         \"serviceAccountsEnabled\": true, \"standardFlowEnabled\": false,${O}"
echo -e "  ${C}         \"directAccessGrantsEnabled\": false, \"clientAuthenticatorType\": \"client-secret\"}'${O}"
echo ""

ADMIN_TOKEN=$(kc_admin_token)

curl -sk -X POST "$KC_URL/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "keycloak-registrar",
    "enabled": true,
    "publicClient": false,
    "serviceAccountsEnabled": true,
    "standardFlowEnabled": false,
    "directAccessGrantsEnabled": false,
    "clientAuthenticatorType": "client-secret"
  }' -w "" -o /dev/null 2>/dev/null

KC_REG_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=keycloak-registrar" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
echo -e "  ${G}✅ Client created: keycloak-registrar (${KC_REG_UUID:0:8}...)${O}"

echo ""
echo -e "  ${D}clientId:                keycloak-registrar${O}"
echo -e "  ${D}serviceAccountsEnabled:  true${O}"
echo -e "  ${D}grant_type:              client_credentials${O}"
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 2: Assign realm-management roles to the service account"

echo -e "${D}The interceptor needs these roles on realm-management:${O}"
echo -e "${W}  - manage-clients${O}         ${D}(create/update/delete sandbox clients)${O}"
echo -e "${W}  - view-clients${O}           ${D}(list clients to check existence)${O}"
echo -e "${W}  - query-clients${O}          ${D}(search clients by clientId)${O}"
echo -e "${W}  - manage-authorization${O}   ${D}(configure FGAP v1 token-exchange permissions)${O}"
echo ""

ADMIN_TOKEN=$(kc_admin_token)
SA_USER=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$KC_REG_UUID/service-account-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.id')
RM_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients/\$CLIENT_UUID/service-account-user${O}"
echo -e "  ${D}  Service account user: ${SA_USER:0:8}...${O}"
echo ""

REQUIRED_ROLES=("manage-clients" "view-clients" "query-clients" "manage-authorization")
for ROLE_NAME in "${REQUIRED_ROLES[@]}"; do
  echo -e "  ${C}> curl -sk -X POST \$KC_URL/admin/realms/$REALM/users/\$SA_USER/role-mappings/clients/\$RM_UUID \\${O}"
  echo -e "  ${C}    -d '[{\"id\": \"\$ROLE_ID\", \"name\": \"${ROLE_NAME}\"}]'${O}"

  ROLE_ID=$(curl -sk --max-time 10 "$KC_URL/admin/realms/$REALM/users/$SA_USER/role-mappings/clients/$RM_UUID/available" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r --arg r "$ROLE_NAME" '.[] | select(.name==$r) | .id' 2>/dev/null)

  if [ -z "$ROLE_ID" ]; then
    echo -e "    ${G}✅ Already assigned${O}"
  else
    curl -sk -X POST "$KC_URL/admin/realms/$REALM/users/$SA_USER/role-mappings/clients/$RM_UUID" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "[{\"id\":\"$ROLE_ID\",\"name\":\"$ROLE_NAME\"}]" -o /dev/null
    echo -e "    ${G}✅ Assigned${O}"
  fi
done

echo ""
echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/users/\$SA_USER/role-mappings/clients/\$RM_UUID${O}"
echo ""
echo -e "  ${W}Assigned roles:${O}"
curl -sk --max-time 10 "$KC_URL/admin/realms/$REALM/users/$SA_USER/role-mappings/clients/$RM_UUID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | "    \(.name)"'
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 3: Create the Kubernetes secret with Keycloak credentials"

echo -e "${D}First, retrieve the client secret from Keycloak:${O}"
echo ""
echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients/\$CLIENT_UUID/client-secret | jq -r '.value'${O}"
echo ""

ADMIN_TOKEN=$(kc_admin_token)
KC_SECRET=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$KC_REG_UUID/client-secret" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.value')
echo -e "  ${D}Secret: ${KC_SECRET:0:8}...${O}"
echo ""

echo -e "${D}Then create the K8s secret:${O}"
echo ""
echo -e "  ${C}> oc -n openshell create secret generic keycloak-registrar-keycloak \\${O}"
echo -e "  ${C}    --from-literal=KEYCLOAK_CLIENT_ID=keycloak-registrar \\${O}"
echo -e "  ${C}    --from-literal=KEYCLOAK_CLIENT_SECRET=\$KC_SECRET${O}"
echo ""

oc -n openshell delete secret keycloak-registrar-keycloak 2>/dev/null
oc -n openshell create secret generic keycloak-registrar-keycloak \
  --from-literal=KEYCLOAK_CLIENT_ID=keycloak-registrar \
  --from-literal=KEYCLOAK_CLIENT_SECRET="$KC_SECRET" 2>&1
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 4: Build the interceptor image on OpenShift"

echo -e "  ${C}> oc -n openshell get bc keycloak-registrar${O}"
echo ""
oc -n openshell get bc keycloak-registrar --no-headers 2>&1
echo ""

echo -e "${D}The BuildConfig pulls from Git and builds with the Dockerfile:${O}"
echo ""
echo -e "  ${D}source:     https://github.com/akram/agent-ops.git${O}"
echo -e "  ${D}branch:     fix/fgap-v1-permissions${O}"
echo -e "  ${D}contextDir: interceptors/keycloak-registrar${O}"
echo -e "  ${D}strategy:   Docker (Rust build + UBI minimal runtime)${O}"
echo ""

echo -e "  ${C}> oc -n openshell get builds --sort-by=.metadata.creationTimestamp | tail -3${O}"
echo ""
oc -n openshell get builds --sort-by=.metadata.creationTimestamp --no-headers 2>&1 | grep keycloak | tail -3
echo ""

echo -e "  ${C}> oc -n openshell get istag keycloak-registrar:latest -o jsonpath='{.image.metadata.name}'${O}"
echo ""
IMAGE_SHA=$(oc -n openshell get istag keycloak-registrar:latest -o jsonpath='{.image.metadata.name}' 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
echo -e "  ${D}Image: ${IMAGE_SHA:0:30}...${O}"
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 5: Deploy the interceptor"

echo -e "  ${C}> cat keycloak-registrar-deployment.yaml${O}"
echo ""
echo -e "  ${D}Key configuration:${O}"
echo -e "  ${W}  GATEWAY_ID${O}              ${D}= openshell${O}"
echo -e "  ${W}  SPIFFE_TRUST_DOMAIN${O}     ${D}= spiffe://openshell.local${O}"
echo -e "  ${W}  KEYCLOAK_URL${O}            ${D}= $KC_URL${O}"
echo -e "  ${W}  KEYCLOAK_REALM${O}          ${D}= $REALM${O}"
echo -e "  ${W}  KEYCLOAK_IDENTITY_PROVIDER${O} ${D}= spire-spiffe (the SPIFFE IDP alias)${O}"
echo -e "  ${W}  GATEWAY_CLIENT_ID${O}       ${D}= spiffe://openshell.local/ns/openshell/sa/openshell${O}"
echo -e "  ${W}  DEFAULT_CLIENT_SCOPES${O}   ${D}= model-api (audience for token exchange)${O}"
echo ""
echo -e "  ${D}Secrets mounted:${O}"
echo -e "  ${D}  /tls/           ← serving cert (auto-generated by OpenShift)${O}"
echo -e "  ${D}  /gateway/       ← gateway Ed25519 public key (from openshell-jwt-keys)${O}"
echo -e "  ${D}  KEYCLOAK_CLIENT_ID/SECRET ← from keycloak-registrar-keycloak secret${O}"
echo ""

echo -e "  ${C}> oc -n openshell get deployment keycloak-registrar${O}"
echo ""
oc -n openshell get deployment keycloak-registrar --no-headers 2>&1
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 6: Register the interceptor with the OpenShell gateway"

echo -e "${D}The gateway needs to know about the interceptor. This is done${O}"
echo -e "${D}in the gateway config (gateway.toml in the openshell-config ConfigMap):${O}"
echo ""
echo -e "  ${C}> oc -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\\.toml}' | grep -A5 interceptor${O}"
echo ""
oc -n openshell get configmap openshell-config -o jsonpath='{.data.gateway\.toml}' 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -A8 'interceptor'
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 7: Verify the interceptor is running"

echo -e "  ${C}> oc -n openshell get pods -l app=keycloak-registrar${O}"
echo ""
oc -n openshell get pods -l app=keycloak-registrar --no-headers 2>&1
echo ""

echo -e "  ${C}> oc -n openshell logs deployment/keycloak-registrar --tail=3${O}"
echo ""
oc -n openshell logs deployment/keycloak-registrar --tail=3 2>&1
echo ""

LAST_LOG=$(oc -n openshell logs deployment/keycloak-registrar --tail=1 2>&1)
if echo "$LAST_LOG" | grep -q 'starting\|registered'; then
  echo -e "  ${G}✅ Interceptor is running and processing events${O}"
else
  echo -e "  ${D}  (check logs for status)${O}"
fi
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 8: Verify FGAP permissions are configured"

echo -e "${D}When a sandbox is created, the interceptor automatically:${O}"
echo -e "${D}  1. Registers the sandbox SPIFFE ID as a Keycloak client${O}"
echo -e "${D}  2. Configures FGAP v1 token-exchange permissions on all targets${O}"
echo ""

ADMIN_TOKEN=$(kc_admin_token)
echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients | jq '.[] | select(.clientAuthenticatorType==\"federated-jwt\")'${O}"
echo ""
curl -sk "$KC_URL/admin/realms/$REALM/clients?max=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.clientAuthenticatorType=="federated-jwt") | "  \(.clientId[0:70])"'
echo ""

MODEL_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=model-api" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
MGMT=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$MODEL_UUID/management/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
TX_PERM=$(echo "$MGMT" | jq -r '.scopePermissions["token-exchange"] // "none"')

if [ "$TX_PERM" != "none" ]; then
  RM_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
  echo -e "  ${C}> model-api token-exchange policies:${O}"
  curl -sk "$KC_URL/admin/realms/$REALM/clients/$RM_UUID/authz/resource-server/policy/$TX_PERM/associatedPolicies" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | "    \(.name)"'
  echo ""
  echo -e "  ${G}✅ FGAP permissions are active${O}"
else
  echo -e "  ${D}  No sandbox registered yet; FGAP will be configured on first sandbox create${O}"
fi
sleep 2

# ═══════════════════════════════════════════════════════
banner "Summary"
echo ""
echo -e "  ${W}Installation steps:${O}"
echo ""
echo -e "  ${G}1.${O} Create Keycloak service account (keycloak-registrar client)"
echo -e "  ${G}2.${O} Assign realm-management roles:"
echo -e "     ${W}manage-clients, view-clients, query-clients, manage-authorization${O}"
echo -e "  ${G}3.${O} Create K8s secret with Keycloak credentials"
echo -e "  ${G}4.${O} Build the interceptor image (oc start-build from Git)"
echo -e "  ${G}5.${O} Deploy (service + deployment + volume mounts)"
echo -e "  ${G}6.${O} Register in gateway config (interceptors section)"
echo -e "  ${G}7.${O} Verify: pods running, logs clean"
echo -e "  ${G}8.${O} Verify: FGAP auto-configured on sandbox creation"
echo ""
echo -e "  ${D}The manage-authorization role is the key addition for FGAP v1.${O}"
echo -e "  ${D}Without it, the interceptor registers clients but cannot configure${O}"
echo -e "  ${D}token-exchange permissions, and exchange silently fails.${O}"
echo ""
echo -e "  ${W}Stack: OCP 4.22 + ZTWIM (SPIRE) + RHBK 26.6 + OpenShell${O}"
sleep 2
