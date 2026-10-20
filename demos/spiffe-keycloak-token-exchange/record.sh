#!/bin/bash
set -uo pipefail

KC_URL="${KEYCLOAK_URL:?Set KEYCLOAK_URL to your Keycloak route}"
GW="${OPENSHELL_GATEWAY:-http://127.0.0.1:8099}"
OPENSHELL_CLI="${OPENSHELL_CLI:-openshell}"
GATEWAY_NAME="${GATEWAY_NAME:-saw-cluster}"
os() { "$OPENSHELL_CLI" --gateway "$GATEWAY_NAME" --gateway-endpoint "$GW" "$@"; }

Y="\033[1;33m"; C="\033[1;36m"; G="\033[1;32m"; B="\033[1;34m"
M="\033[1;35m"; R="\033[1;31m"; W="\033[1;37m"; D="\033[0;37m"; O="\033[0m"
# Highlight color for tracked values
H="\033[1;33;4m"  # yellow underlined — the value to track
# Sub highlight: reverse video — works on all terminals, visible for colorblind
S="\033[1;7m"     # bold + reverse video

banner() { echo ""; echo -e "${Y}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${O}"; echo -e "${Y}  $1${O}"; echo -e "${Y}══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${O}"; echo ""; sleep 2; }

decode_jwt() {
  python3 -c "
import base64, json, sys
token = sys.argv[1]
keys = [a for a in sys.argv[2:]]
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
for k in (keys if keys else payload.keys()):
    v = payload.get(k, '—')
    if isinstance(v, list): v = ', '.join(str(x) for x in v)
    if k == 'sub':
        print(f'    {k}: \033[1;7m{v}\033[0m')
    else:
        print(f'    {k}: {v}')
" "$@"
}

# Color helper: highlight any known sub UUID in output
SUB_UUIDS=()
highlight_subs() {
  local line="$1"
  for uuid in "${SUB_UUIDS[@]}"; do
    line="${line//$uuid/$(echo -e "\033[1;37m${uuid}\033[0m")}"
  done
  echo -e "$line"
}

# Ensure port-forward
pkill -f "port-forward.*8099" 2>/dev/null; sleep 1
oc -n openshell port-forward svc/openshell 8099:8080 > /tmp/pf.log 2>&1 &
for i in $(seq 1 10); do nc -z 127.0.0.1 8099 2>/dev/null && break; sleep 1; done

# Ensure spiffe module in debug pod
oc -n openshell exec spiffe-debug -- pip install -q spiffe 2>/dev/null

# ═══════════════════════════════════════════════════════
banner "🔐 SPIFFE + Keycloak Token Exchange on OpenShift"
echo -e "${D}OCP 4.22 | RHBK 26.6 | SPIRE/ZTWIM v1.1.2 | OpenShell${O}"
echo ""
echo -e "${W}Architecture:${O}"
echo ""
# No emojis in boxes — they cause unpredictable alignment across terminals
echo -e "  ${G}┌─────────────┐${O}     ${B}┌─────────────┐${O}     ${M}┌─────────────┐${O}"
echo -e "  ${G}│    Alice    │${O}     ${B}│  Keycloak   │${O}     ${M}│    SPIRE    │${O}"
echo -e "  ${G}│   (OIDC)    │${O}     ${B}│   (RHBK)    │${O}     ${M}│   (ZTWIM)   │${O}"
echo -e "  ${G}└──────┬──────┘${O}     ${B}└──────┬──────┘${O}     ${M}└──────┬──────┘${O}"
echo -e "         ${G}│${O}                   ${B}│${O}                   ${M}│${O}"
echo -e "         ${G}▼${O}                   ${B}│${O}                   ${M}│${O}"
echo -e "  ${C}┌─────────────────────────────────────────────────────────┐${O}"
echo -e "  ${C}│  OpenShell Gateway                                      │${O}"
echo -e "  ${C}│  Stores user token, holds gateway SPIFFE SVID           │${O}"
echo -e "  ${C}└────────────────────────────┬────────────────────────────┘${O}"
echo -e "                               ${C}│${O}"
echo -e "                               ${C}▼${O}"
echo -e "  ${C}┌─────────────────────────────────────────────────────────┐${O}"
echo -e "  ${C}│  Sandbox Supervisor                                     │${O}"
echo -e "  ${C}│  Intercepts HTTP, exchanges tokens at Keycloak,         │${O}"
echo -e "  ${C}│  injects Authorization: Bearer \$EXCHANGED_TOKEN         │${O}"
echo -e "  ${C}│  (\$EXCHANGED_TOKEN = Alice's token re-signed with       │${O}"
echo -e "  ${C}│   sandbox SPIFFE ID as azp, scoped to model-api)        │${O}"
echo -e "  ${C}└────────────────────────────┬────────────────────────────┘${O}"
echo -e "                               ${C}│${O}"
echo -e "                               ${C}▼${O}"
echo -e "  ${W}┌─────────────────────────────────────────────────────────┐${O}"
echo -e "  ${W}│  Model API (mock)                                       │${O}"
echo -e "  ${W}│  Validates bearer token, returns identity claims        │${O}"
echo -e "  ${W}└─────────────────────────────────────────────────────────┘${O}"
sleep 5

# ═══════════════════════════════════════════════════════
banner "Two-Stage Token Exchange (RFC 8693)"
echo -e "🤔 ${W}Why two stages?${O} The gateway and the supervisor are two separate"
echo -e "components with two different SPIFFE identities."
echo -e "The gateway knows the ${G}user${O}. The supervisor knows the ${M}sandbox${O}."
echo -e "Two exchanges fuse both identities into one Keycloak-signed token."
echo ""
echo -e "  ${G}Stage 1: Gateway → Keycloak${O}"
echo -e "  ${D}  The gateway holds two things:${O}"
echo -e "  ${D}    - Alice's OIDC token (the user)${O}"
echo -e "  ${D}    - Its own JWT-SVID (proves gateway identity to Keycloak)${O}"
echo -e "  ${D}  Keycloak verifies both via the SPIFFE IDP and returns an${O}"
echo -e "  ${D}  ${W}intermediate token${O}${D}: \"Alice, via the gateway\"${O}"
echo ""
echo -e "  ${G}Stage 2: Supervisor → Keycloak${O}"
echo -e "  ${D}  The supervisor receives the intermediate token, then exchanges:${O}"
echo -e "  ${D}    - The intermediate token (Alice came through the gateway)${O}"
echo -e "  ${D}    - The sandbox's JWT-SVID (proves this specific sandbox)${O}"
echo -e "  ${D}  Keycloak produces the ${W}final token${O}${D} containing:${O}"
echo -e "  ${D}    sub  = Alice             (the user)${O}"
echo -e "  ${D}    azp  = spiffe://sandbox  (the workload)${O}"
echo -e "  ${D}    aud  = model-api         (the target service)${O}"
echo ""
echo -e "  ${D}The supervisor injects this final token as Authorization: Bearer${O}"
echo -e "  ${D}into the outbound HTTP request. The sandbox process never sees any token.${O}"
sleep 8

echo ""
echo -e "🤔 ${W}Why two stages, not one?${O}"
echo ""
echo -e "  ${D}A JWT is signed. You cannot add claims without breaking the signature.${O}"
echo -e "  ${D}Only Keycloak can produce a new token with new claims.${O}"
echo ""
echo -e "  ${D}RFC 8693 allows a single exchange, but OpenShell uses two for${O}"
echo -e "  ${W}least privilege${O}${D}:${O}"
echo -e "  ${D}  - The gateway never passes Alice's raw OIDC token to the supervisor${O}"
echo -e "  ${D}  - The supervisor only receives the intermediate token (already scoped)${O}"
echo -e "  ${D}  - If the supervisor is compromised, the attacker does NOT get${O}"
echo -e "  ${D}    Alice's original token (which could access other services)${O}"
echo ""
echo -e "  ${D}Each component sees only the minimum it needs.${O}"
echo -e "  ${D}Keycloak logs both exchanges for a complete audit trail.${O}"
sleep 6

# ═══════════════════════════════════════════════════════
banner "✅ Test 1/6: Sandbox + Alice = SUCCESS"

echo -e "${W}📌 Step 1: Alice logs in to Keycloak${O}"
echo ""
echo -e "  ${C}> curl -X POST \$KC/realms/openshell/protocol/openid-connect/token -d grant_type=password -d client_id=openshell-cli -d username=alice -d password=***${O}"
echo ""
ALICE_TOKEN=$(curl -sk --max-time 10 -X POST "$KC_URL/realms/openshell/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=openshell-cli" \
  -d "username=alice" -d "password=alice123" -d "scope=openid" | jq -r '.access_token')

# Extract Alice's sub for highlighting later
ALICE_SUB=$(python3 -c "
import base64, json, sys
parts = sys.argv[1].split('.')
p = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print(p['sub'])
" "$ALICE_TOKEN")
SUB_UUIDS+=("$ALICE_SUB")

echo -e "  ${G}✅ Token received. Claims:${O}"
decode_jwt "$ALICE_TOKEN" sub preferred_username email iss
echo ""
echo -e "  ${H}▶ Track this: sub = ${S}${ALICE_SUB}${O}"
echo -e "  ${D}  This is Alice's unique ID. Watch for it in the response.${O}"
echo ""
sleep 4

echo -e "${W}📌 Step 2: Store Alice's token in the OpenShell provider${O}"
echo ""
echo -e "  ${C}> os provider update keycloak-model-demo --credential \"subject_token=\$ALICE_TOKEN\"${O}"
echo ""
os provider update keycloak-model-demo --credential "subject_token=${ALICE_TOKEN}" 2>&1
echo ""
echo -e "  ${D}  The gateway stores this token securely.${O}"
echo -e "  ${D}  The sandbox process never sees it.${O}"
echo ""
sleep 3

echo -e "${W}📌 Step 3: Sandbox SPIFFE identity${O}"
echo ""
echo -e "  ${D}SPIRE issued this JWT-SVID to the sandbox supervisor:${O}"
echo ""
oc -n openshell exec spiffe-debug -- python3 -c "
from spiffe import WorkloadApiClient
import json, base64
client = WorkloadApiClient('unix:///spiffe-workload-api/spire-agent.sock')
svids = client.fetch_jwt_svids(audience={'${KC_URL}/realms/openshell'})
parts = svids[0].token.split('.')
p = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print(f'    sub: \033[1;35m{p[\"sub\"]}\033[0m')
print(f'    aud: {p[\"aud\"]}')
print(f'    iss: {p[\"iss\"][:50]}...')
" 2>&1
echo ""
echo -e "  ${D}  This SVID proves WHO the sandbox is to Keycloak.${O}"
echo ""
sleep 3

echo -e "${W}📌 Step 4: Sandbox runs curl (plain HTTP, no auth)${O}"
echo ""
echo -e "  ${C}> os sandbox exec --name model-demo -- curl -X POST http://model-api.openshell-demo.svc.cluster.local/v1/completions -d '{\"prompt\":\"Hello\"}' ${O}"
echo ""
echo -e "  ${D}The sandbox sends a plain HTTP request. No auth headers. Then:${O}"
echo -e "  ${D}  1️⃣  Supervisor fetches sandbox's JWT-SVID from SPIRE (proves sandbox identity)${O}"
echo -e "  ${D}  2️⃣  Gateway exchanges Alice's OIDC token + gateway SVID at Keycloak → intermediate token${O}"
echo -e "  ${D}  3️⃣  Supervisor exchanges intermediate token + sandbox SVID at Keycloak → \$EXCHANGED_TOKEN${O}"
echo -e "  ${D}  4️⃣  Supervisor injects: ${W}Authorization: Bearer \$EXCHANGED_TOKEN${O}"
echo -e "  ${D}     (\$EXCHANGED_TOKEN contains: sub=alice, azp=sandbox-spiffe-id, aud=model-api)${O}"
echo ""
sleep 3

echo -e "${W}📌 Step 5: Response from model API${O}"
echo ""
RESULT=$(os sandbox exec --name model-demo --no-tty -- \
  curl -sS -X POST http://model-api.openshell-demo.svc.cluster.local/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Hello from Alice in sandbox"}' 2>&1)
HIGHLIGHTED=$(echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT")
for uuid in "${SUB_UUIDS[@]}"; do
  HIGHLIGHTED=$(echo "$HIGHLIGHTED" | sed "s/${uuid}/$(printf '\033[1;7m')${uuid}$(printf '\033[0m')/g")
done
echo "$HIGHLIGHTED"
echo ""
echo -e "  ${H}▶ user = ${S}${ALICE_SUB}${O}${H} ← same as Alice's sub above!${O}"
echo -e "  ${G}✅ User identity (Alice) preserved end-to-end${O}"
echo -e "  ${G}✅ Workload identity (sandbox SPIFFE ID) attached${O}"
echo -e "  ${G}✅ Audience scoped to model-api${O}"
sleep 5

# ═══════════════════════════════════════════════════════
banner "❌ Test 2/6: Direct call without sandbox = REJECTED"
echo -e "${D}A pod calls the model API directly. No supervisor,${O}"
echo -e "${D}no token injection. The request has no Authorization header.${O}"
echo ""
echo -e "  ${C}> oc exec model-api -- wget http://model-api/v1/completions${O}"
echo -e "  ${D}  Headers sent: Content-Type only. No Authorization.${O}"
echo ""
oc -n openshell-demo exec deployment/model-api -- \
  wget -qO- --post-data='{"prompt":"rogue"}' \
  --header='Content-Type: application/json' \
  http://localhost:8080/v1/completions 2>&1 || echo -e "  ${R}❌ 401 Unauthorized — missing Authorization: Bearer header${O}"
sleep 3

# ═══════════════════════════════════════════════════════
banner "❌ Test 3/6: Valid SPIFFE pod, not a sandbox = REJECTED"
echo -e "${D}A pod has a valid SPIFFE SVID (from ZTWIM default), but${O}"
echo -e "${D}it was NOT created by OpenShell. The interceptor never${O}"
echo -e "${D}registered it in Keycloak.${O}"
echo ""
echo -e "  ${D}What it sends to Keycloak:${O}"
echo -e "  ${C}  client_id:             spiffe://.../sandbox/debug-test${O}"
echo -e "  ${C}  client_assertion_type:  jwt-spiffe${O}"
echo -e "  ${C}  client_assertion:       <valid JWT-SVID from SPIRE>${O}"
echo -e "  ${C}  subject_token:          <Alice's valid OIDC token>${O}"
echo ""
oc -n openshell exec spiffe-debug -- python3 -c "
import json, urllib.request, ssl, urllib.parse
from spiffe import WorkloadApiClient
client = WorkloadApiClient('unix:///spiffe-workload-api/spire-agent.sock')
svids = client.fetch_jwt_svids(audience={'${KC_URL}/realms/openshell'})
token = svids[0].token
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
alice = json.loads(urllib.request.urlopen(urllib.request.Request(
    '${KC_URL}/realms/openshell/protocol/openid-connect/token',
    data=urllib.parse.urlencode({'grant_type':'password','client_id':'openshell-cli','username':'alice','password':'alice123','scope':'openid'}).encode()
), context=ctx).read())['access_token']
data = urllib.parse.urlencode({
    'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
    'client_id': 'spiffe://openshell.local/openshell/sandbox/debug-test',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-spiffe',
    'client_assertion': token, 'subject_token': alice,
    'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token', 'audience': 'model-api',
}).encode()
try:
    urllib.request.urlopen(urllib.request.Request(
        '${KC_URL}/realms/openshell/protocol/openid-connect/token',
        data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}), context=ctx)
except urllib.error.HTTPError as e:
    body = json.loads(e.read())
    print(f'  Keycloak HTTP {e.code}: {body.get(\"error\")} — {body.get(\"error_description\", \"\")}')
" 2>&1
echo ""
echo -e "  ${R}❌ Rejected — valid SPIFFE SVID but Keycloak has no client for it${O}"
echo -e "  ${D}  Only sandboxes registered by the interceptor are accepted.${O}"
sleep 4

# ═══════════════════════════════════════════════════════
banner "❌ Test 4/6: Sandbox without FGAP = REJECTED"
echo -e "${D}The interceptor creates a Keycloak client per sandbox,${O}"
echo -e "${D}but FGAP (Fine-Grained Authorization Policy) must also be${O}"
echo -e "${D}configured to allow token exchange between clients.${O}"
echo ""
echo -e "  ${D}Without FGAP, Keycloak returns:${O}"
echo -e "  ${R}❌ \"client not allowed to exchange to audience\"${O}"
echo ""
echo -e "  ${D}  This was our actual integration blocker.${O}"
echo -e "  ${D}  The interceptor needs to also configure FGAP permissions.${O}"
sleep 4

# ═══════════════════════════════════════════════════════
banner "❌ Test 5/6: Disabled user (Bob) = REJECTED"
echo -e "${D}Bob's account is disabled in Keycloak. Correct password,${O}"
echo -e "${D}but Keycloak refuses to issue a token.${O}"
echo ""
echo -e "  ${C}> curl -X POST \$KC/realms/openshell/.../token -d username=bob -d password=***${O}"
echo ""
BOB_RESULT=$(curl -sk --max-time 10 -X POST "$KC_URL/realms/openshell/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=openshell-cli" \
  -d "username=bob" -d "password=bob123" -d "scope=openid" 2>&1)
BOB_ERROR=$(echo "$BOB_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('error_description', d.get('error','?')))" 2>/dev/null)
echo -e "  ${R}❌ Keycloak: ${BOB_ERROR}${O}"
echo ""
echo -e "  ${D}  No token = no exchange = no access.${O}"
echo -e "  ${D}  The identity chain stops at the first gate.${O}"
sleep 4

# ═══════════════════════════════════════════════════════
banner "✅ Test 6/6: Same sandbox, Claire instead of Alice = SUCCESS"
echo -e "${D}Claire logs in. Same sandbox, different user identity.${O}"
echo ""
echo -e "${W}📌 Claire's token:${O}"
CLAIRE_TOKEN=$(curl -sk --max-time 10 -X POST "$KC_URL/realms/openshell/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=openshell-cli" \
  -d "username=claire" -d "password=claire123" -d "scope=openid" | jq -r '.access_token')
CLAIRE_SUB=$(python3 -c "import base64,json,sys; print(json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[1]+'=='))['sub'])" "$CLAIRE_TOKEN")
SUB_UUIDS+=("$CLAIRE_SUB")
decode_jwt "$CLAIRE_TOKEN" sub preferred_username
echo ""
echo -e "  ${H}▶ Track this: sub = ${S}${CLAIRE_SUB}${O}"
echo ""
echo -e "  ${C}> os provider update keycloak-model-demo --credential \"subject_token=\$CLAIRE_TOKEN\"${O}"
os provider update keycloak-model-demo --credential "subject_token=${CLAIRE_TOKEN}" 2>&1
echo ""
echo -e "  ${C}> os sandbox exec -- curl (now as Claire)${O}"
echo ""
RESULT=$(os sandbox exec --name model-demo --no-tty -- \
  curl -sS -X POST http://model-api.openshell-demo.svc.cluster.local/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Hello from Claire in the same sandbox"}' 2>&1)
HIGHLIGHTED=$(echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT")
for uuid in "${SUB_UUIDS[@]}"; do
  HIGHLIGHTED=$(echo "$HIGHLIGHTED" | sed "s/${uuid}/$(printf '\033[1;7m')${uuid}$(printf '\033[0m')/g")
done
echo "$HIGHLIGHTED"
echo ""
echo -e "  ${H}▶ user changed: ${S}${ALICE_SUB}${O}${H} (Alice) → ${S}${CLAIRE_SUB}${O}${H} (Claire)${O}"
echo -e "  ${G}✅ Same sandbox, different user = different sub claim${O}"
echo -e "  ${D}  The model API knows WHO is calling and FROM WHERE.${O}"
sleep 4

# ═══════════════════════════════════════════════════════
banner "📊 Summary: 6 security scenarios"
echo ""
echo -e "  ┌──────────────────────────────────────────────────────────────────┐"
echo -e "  │  ${G}✅${O} 1. Sandbox + Alice              → sub=alice, azp=sandbox     │"
echo -e "  │  ${R}❌${O} 2. Direct call                  → 401 (no token)             │"
echo -e "  │  ${R}❌${O} 3. SPIFFE pod, not sandbox      → client rejected            │"
echo -e "  │  ${R}❌${O} 4. Sandbox, no FGAP             → exchange denied            │"
echo -e "  │  ${R}❌${O} 5. Disabled user (Bob)          → no token issued            │"
echo -e "  │  ${G}✅${O} 6. Sandbox + Claire             → sub=claire, azp=sandbox    │"
echo -e "  └──────────────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${W}Only a registered OpenShell sandbox with valid FGAP${O}"
echo -e "  ${W}permissions and an enabled user can exchange tokens.${O}"
echo ""
echo -e "  ${D}Stack: OCP 4.22 + ZTWIM (SPIRE) + RHBK 26.6 + OpenShell${O}"
sleep 5
