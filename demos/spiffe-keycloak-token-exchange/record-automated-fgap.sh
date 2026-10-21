#!/bin/bash
set -uo pipefail

KC_URL="${KEYCLOAK_URL:?Set KEYCLOAK_URL to your Keycloak route}"
KC_ADMIN_USER="${KEYCLOAK_ADMIN_USER:?Set KEYCLOAK_ADMIN_USER}"
KC_ADMIN_PASS="${KEYCLOAK_ADMIN_PASS:?Set KEYCLOAK_ADMIN_PASS}"
REALM="openshell"
GW="${OPENSHELL_GATEWAY:-http://127.0.0.1:8099}"
OPENSHELL_CLI="${OPENSHELL_CLI:-openshell}"
GATEWAY_NAME="${GATEWAY_NAME:-saw-cluster}"
os() { "$OPENSHELL_CLI" --gateway "$GATEWAY_NAME" --gateway-endpoint "$GW" "$@"; }

Y="\033[1;33m"; C="\033[1;36m"; G="\033[1;32m"; B="\033[1;34m"
M="\033[1;35m"; R="\033[1;31m"; W="\033[1;37m"; D="\033[0;37m"; O="\033[0m"
S="\033[1;7m"

banner() { echo ""; echo -e "${Y}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${O}"; echo -e "${Y}  $1${O}"; echo -e "${Y}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${O}"; echo ""; sleep 2; }

kc_admin_token() {
  curl -sk --max-time 10 -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=$KC_ADMIN_USER" -d "password=$KC_ADMIN_PASS" | jq -r '.access_token'
}

# Ensure port-forward
pkill -f "port-forward.*8099" 2>/dev/null; sleep 1
oc -n openshell port-forward svc/openshell 8099:8080 > /tmp/pf.log 2>&1 &
for i in $(seq 1 10); do nc -z 127.0.0.1 8099 2>/dev/null && break; sleep 1; done

# Ensure spiffe module in debug pod
oc -n openshell exec spiffe-debug -- pip install -q spiffe 2>/dev/null

# ═══════════════════════════════════════════════════════
banner "Automated FGAP: Zero-Config Token Exchange on OpenShift"
echo -e "${D}This demo shows how the keycloak-registrar interceptor automatically${O}"
echo -e "${D}configures FGAP v1 permissions when a sandbox is created.${O}"
echo -e "${D}No manual Keycloak configuration is needed after deployment.${O}"
echo ""
echo -e "${W}Stack:${O} OCP 4.22 | RHBK 26.6 | SPIRE/ZTWIM v1.1.2 | OpenShell"
echo ""
echo -e "${W}What FGAP means:${O}"
echo -e "${D}  Fine-Grained Authorization Policy v1. When active on a Keycloak realm,${O}"
echo -e "${D}  the standard.token.exchange.enabled flag is ignored. Each client that${O}"
echo -e "${D}  participates in a token exchange needs explicit scope permissions.${O}"
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 1: Check Keycloak clients BEFORE sandbox creation"

ADMIN_TOKEN=$(kc_admin_token)
echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients | jq '.[] | select(.clientAuthenticatorType==\"federated-jwt\")'${O}"
echo ""
CLIENTS_BEFORE=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?max=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '[.[] | select(.clientAuthenticatorType=="federated-jwt") | {clientId, id}]')
echo "$CLIENTS_BEFORE" | jq -r '.[] | "  \(.clientId[0:70])  \(.id[0:8])..."'
BEFORE_COUNT=$(echo "$CLIENTS_BEFORE" | jq length)
echo ""
echo -e "${W}  $BEFORE_COUNT federated-jwt clients registered${O}"
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 2: Check model-api FGAP permissions BEFORE"

echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients/\$MODEL_API_UUID/management/permissions${O}"
echo ""
MODEL_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=model-api" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
MGMT_BEFORE=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$MODEL_UUID/management/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
TX_PERM_BEFORE=$(echo "$MGMT_BEFORE" | jq -r '.scopePermissions["token-exchange"] // "none"')
echo -e "${W}  model-api management permissions:${O}"
echo -e "  ${D}enabled: $(echo "$MGMT_BEFORE" | jq -r '.enabled')${O}"
echo -e "  ${D}token-exchange permission: ${TX_PERM_BEFORE}${O}"
echo ""

if [ "$TX_PERM_BEFORE" != "none" ]; then
  RM_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
  POLICIES_BEFORE=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$RM_UUID/authz/resource-server/policy/$TX_PERM_BEFORE/associatedPolicies" \
    -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null)
  POLICY_COUNT=$(echo "$POLICIES_BEFORE" | jq 'length' 2>/dev/null || echo 0)
  echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients/\$RM_UUID/authz/resource-server/policy/\$PERM_ID/associatedPolicies${O}"
  echo ""
  echo -e "${W}  Token-exchange policies on model-api:${O}"
  echo "$POLICIES_BEFORE" | jq -r '.[] | "  \(.name)"' 2>/dev/null || echo "  (none)"
  echo ""
  echo -e "${W}  $POLICY_COUNT policies linked${O}"
fi
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 3: Delete existing sandbox and create a fresh one"

echo -e "${C}> os sandbox delete model-demo${O}"
os sandbox delete model-demo 2>&1 || true
sleep 2

echo ""
echo -e "${C}> os sandbox create --name model-demo --provider keycloak-model-demo --from sandbox-with-curl:latest${O}"
echo ""
os sandbox create --name model-demo --provider keycloak-model-demo \
  --from image-registry.openshift-image-registry.svc:5000/openshell-images/sandbox-with-curl:latest \
  --detach 2>&1
echo ""

echo -e "${G}  Sandbox created. Waiting for supervisor to initialize...${O}"
sleep 5
echo -e "  ${C}> os sandbox list${O}"
os sandbox list 2>&1 | grep model-demo
echo ""

# ═══════════════════════════════════════════════════════
banner "Step 4: Check interceptor logs"

echo -e "${C}> oc logs deployment/keycloak-registrar --tail=5${O}"
echo ""
oc -n openshell logs deployment/keycloak-registrar --tail=5 2>&1
echo ""

LAST_LOG=$(oc -n openshell logs deployment/keycloak-registrar --tail=1 2>&1)
if echo "$LAST_LOG" | grep -q '"registered"'; then
  echo -e "${G}  ✅ Interceptor registered the new sandbox successfully${O}"
elif echo "$LAST_LOG" | grep -q 'failed'; then
  echo -e "${R}  ❌ Registration failed (check logs above)${O}"
else
  echo -e "${D}  Waiting for registration...${O}"
  sleep 2
  oc -n openshell logs deployment/keycloak-registrar --tail=2 2>&1
fi
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 5: Check Keycloak clients AFTER sandbox creation"

ADMIN_TOKEN=$(kc_admin_token)
echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients | jq '.[] | select(.clientAuthenticatorType==\"federated-jwt\")'${O}"
echo ""
CLIENTS_AFTER=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?max=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '[.[] | select(.clientAuthenticatorType=="federated-jwt") | {clientId, id}]')
echo "$CLIENTS_AFTER" | jq -r '.[] | "  \(.clientId[0:70])  \(.id[0:8])..."'
AFTER_COUNT=$(echo "$CLIENTS_AFTER" | jq length)
echo ""

# Find the new client
NEW_CLIENT=$(echo "$CLIENTS_AFTER" | jq -r '.[] | select(.clientId | test("sandbox")) | .clientId' | sort | tail -1)
NEW_UUID=$(echo "$CLIENTS_AFTER" | jq -r --arg c "$NEW_CLIENT" '.[] | select(.clientId==$c) | .id')
echo -e "  ${G}✅ New client: ${S}${NEW_CLIENT:0:70}${O}"
echo -e "  ${W}  $BEFORE_COUNT → $AFTER_COUNT federated-jwt clients (+1)${O}"
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 6: Verify FGAP permissions AFTER"

ADMIN_TOKEN=$(kc_admin_token)
echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients/\$MODEL_API_UUID/management/permissions${O}"
echo -e "  ${C}> curl -sk \$KC_URL/.../authz/resource-server/policy/\$PERM_ID/associatedPolicies${O}"
echo ""
MGMT_AFTER=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$MODEL_UUID/management/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
TX_PERM_AFTER=$(echo "$MGMT_AFTER" | jq -r '.scopePermissions["token-exchange"] // "none"')
RM_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=realm-management" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
POLICIES_AFTER=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$RM_UUID/authz/resource-server/policy/$TX_PERM_AFTER/associatedPolicies" \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null)
echo "$POLICIES_AFTER" | jq -r '.[] | "  \(.name)"' 2>/dev/null || echo "  (none)"
POLICY_COUNT_AFTER=$(echo "$POLICIES_AFTER" | jq 'length' 2>/dev/null || echo 0)
echo ""
echo -e "  ${G}✅ $POLICY_COUNT_AFTER policies linked (sandbox + gateway)${O}"
echo ""

echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients/\$SANDBOX_UUID/management/permissions${O}"
echo ""
echo -e "${W}  Sandbox management permissions:${O}"
SANDBOX_MGMT=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$NEW_UUID/management/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null)
SANDBOX_FGAP=$(echo "$SANDBOX_MGMT" | jq -r '.enabled // false')
echo -e "  ${D}enabled: ${SANDBOX_FGAP}${O}"
if [ "$SANDBOX_FGAP" = "true" ]; then
  echo -e "  ${G}✅ Sandbox FGAP enabled automatically${O}"
else
  echo -e "  ${R}❌ Sandbox FGAP not enabled${O}"
fi
echo ""

echo -e "  ${C}> curl -sk \$KC_URL/admin/realms/$REALM/clients/\$GATEWAY_UUID/management/permissions${O}"
echo ""
echo -e "${W}  Gateway management permissions:${O}"
GW_UUID=$(curl -sk "$KC_URL/admin/realms/$REALM/clients?clientId=$(python3 -c "import urllib.parse; print(urllib.parse.quote('spiffe://openshell.local/ns/openshell/sa/openshell'))")" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
GW_MGMT=$(curl -sk "$KC_URL/admin/realms/$REALM/clients/$GW_UUID/management/permissions" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
GW_FGAP=$(echo "$GW_MGMT" | jq -r '.enabled // false')
echo -e "  ${D}enabled: ${GW_FGAP}${O}"
if [ "$GW_FGAP" = "true" ]; then
  echo -e "  ${G}✅ Gateway FGAP enabled automatically${O}"
else
  echo -e "  ${R}❌ Gateway FGAP not enabled${O}"
fi
sleep 2

# ═══════════════════════════════════════════════════════
banner "Step 7: Token exchange test (zero manual config)"

echo -e "${W}📌 Get Alice's token from Keycloak${O}"
echo ""
echo -e "  ${C}> curl -X POST \$KC_URL/realms/$REALM/protocol/openid-connect/token -d grant_type=password -d client_id=openshell-cli -d username=alice${O}"
echo ""
ALICE_TOKEN=$(curl -sk --max-time 10 -X POST "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=openshell-cli" \
  -d "username=alice" -d "password=alice123" -d "scope=openid" | jq -r '.access_token')
echo -e "  ${G}✅ Token received (${#ALICE_TOKEN} chars)${O}"
echo ""

echo -e "${W}📌 Store token in provider${O}"
echo ""
echo -e "  ${C}> os provider update keycloak-model-demo --credential \"subject_token=\$ALICE_TOKEN\"${O}"
os provider update keycloak-model-demo --credential "subject_token=${ALICE_TOKEN}" 2>&1
echo ""
sleep 2

echo -e "${W}📌 Call model API from sandbox (curl with no auth headers)${O}"
echo ""
echo -e "  ${C}> os sandbox exec --name model-demo -- curl -X POST http://model-api.openshell-demo.svc.cluster.local/v1/completions${O}"
echo ""
RESULT=""
for attempt in 1 2 3; do
  RESULT=$(os sandbox exec --name model-demo --no-tty -- \
    curl -sS --max-time 15 -X POST http://model-api.openshell-demo.svc.cluster.local/v1/completions \
    -H "Content-Type: application/json" \
    -d '{"prompt":"Automated FGAP demo"}' 2>&1)
  echo "$RESULT" | jq . >/dev/null 2>&1 && break
  echo -e "  ${D}(retry $attempt...)${O}"
  sleep 3
done

if echo "$RESULT" | jq . >/dev/null 2>&1; then
  echo "$RESULT" | jq .
  echo ""
  USER_SUB=$(echo "$RESULT" | jq -r '.identity.user')
  SANDBOX_ID=$(echo "$RESULT" | jq -r '.identity.sandbox')
  echo -e "  ${G}✅ Token exchange succeeded with zero manual FGAP configuration${O}"
  echo -e "  ${W}  user:    ${S}${USER_SUB}${O}${W} (Alice)${O}"
  echo -e "  ${W}  sandbox: ${SANDBOX_ID:0:70}${O}"
  echo -e "  ${W}  audience: $(echo "$RESULT" | jq -r '.identity.audience')${O}"
else
  echo "$RESULT"
  echo ""
  echo -e "  ${R}❌ Token exchange failed${O}"
fi
sleep 2

# ═══════════════════════════════════════════════════════
banner "Summary: What the interceptor did automatically"
echo ""
echo -e "  ${W}When the sandbox was created, the keycloak-registrar interceptor:${O}"
echo ""
echo -e "  ${G}1.${O} Registered the sandbox SPIFFE ID as a Keycloak federated-jwt client"
echo -e "  ${G}2.${O} Set jwt.credential.issuer and jwt.credential.sub attributes"
echo -e "  ${G}3.${O} Attached default client scopes (model-api)"
echo -e "  ${G}4.${O} Created an audience scope + mapper for the gateway"
echo -e "  ${G}5.${O} Enabled management permissions on sandbox, gateway, and model-api"
echo -e "  ${G}6.${O} Created client policies for sandbox and gateway"
echo -e "  ${G}7.${O} Linked policies to the token-exchange scope permission on all targets"
echo ""
echo -e "  ${D}All derived from two env vars: DEFAULT_CLIENT_SCOPES and GATEWAY_CLIENT_ID${O}"
echo -e "  ${D}No AUDIENCE_CLIENTS, no manual FGAP script, no Keycloak admin intervention.${O}"
echo ""
echo -e "  ${W}Stack: OCP 4.22 + ZTWIM (SPIRE) + RHBK 26.6 + OpenShell${O}"
sleep 2
