// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keycloak admin calls that register a sandbox SPIFFE ID as a federated client.
//!
//! Object names match grs/perilinkle (client = SPIFFE ID, audience client scope =
//! SPIFFE ID), so this interceptor and that controller can manage the same realm.

use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct KeycloakConfig {
    /// Base URL, e.g. `http://keycloak.openshell.svc.cluster.local`.
    pub base_url: String,
    /// Realm holding the sandbox clients; the service account lives in it too.
    pub realm: String,
    /// Service-account client (`client_credentials`) with realm-management roles.
    pub client_id: String,
    pub client_secret: String,
    /// Alias of the SPIFFE identity provider in the realm.
    pub identity_provider: String,
    /// Client ID of the OpenShell gateway's federated client.
    pub gateway_client_id: String,
    /// Client scopes (by name) every sandbox client gets as default scopes,
    /// typically one audience scope per target API.
    pub default_scopes: Vec<String>,
    /// Client IDs of the audience services that sandbox clients may exchange
    /// tokens to. When FGAP v1 is active, the interceptor configures
    /// token-exchange scope permissions on these clients for each sandbox.
    pub audience_clients: Vec<String>,
}

pub struct KeycloakAdmin {
    config: KeycloakConfig,
    http: reqwest::Client,
    token: Mutex<Option<(String, Instant)>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl KeycloakAdmin {
    pub fn new(config: KeycloakConfig) -> Self {
        // reqwest is built without a bundled provider; install aws-lc once.
        // Errors only mean a provider is already installed.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            token: Mutex::new(None),
        }
    }

    /// Creates or updates the sandbox's federated client, its default scopes,
    /// and the audience scope that lets the gateway address tokens to it.
    pub async fn ensure_sandbox(&self, spiffe_id: &str) -> Result<(), String> {
        let representation = json!({
            "clientId": spiffe_id,
            "protocol": "openid-connect",
            "publicClient": false,
            "clientAuthenticatorType": "federated-jwt",
            "standardFlowEnabled": false,
            "directAccessGrantsEnabled": false,
            "serviceAccountsEnabled": false,
            "attributes": {
                "jwt.credential.issuer": self.config.identity_provider,
                "jwt.credential.sub": spiffe_id,
                "standard.token.exchange.enabled": "true",
            },
        });
        let client = match self.client_uuid(spiffe_id).await? {
            Some(uuid) => {
                let mut update = representation;
                update["id"] = json!(uuid);
                self.admin(Method::PUT, &format!("/clients/{uuid}"), Some(&update))
                    .await?;
                uuid
            }
            None => {
                self.admin(Method::POST, "/clients", Some(&representation))
                    .await?;
                self.client_uuid(spiffe_id)
                    .await?
                    .ok_or_else(|| format!("client {spiffe_id} missing after create"))?
            }
        };

        for name in &self.config.default_scopes {
            let scope = self
                .scope_uuid(name)
                .await?
                .ok_or_else(|| format!("default client scope {name:?} not found in realm"))?;
            self.admin(
                Method::PUT,
                &format!("/clients/{client}/default-client-scopes/{scope}"),
                None,
            )
            .await?;
        }

        let audience_scope = self.ensure_audience_scope(spiffe_id).await?;
        let gateway = self
            .client_uuid(&self.config.gateway_client_id)
            .await?
            .ok_or_else(|| {
                format!(
                    "gateway client {:?} not found",
                    self.config.gateway_client_id
                )
            })?;
        self.admin(
            Method::PUT,
            &format!("/clients/{gateway}/default-client-scopes/{audience_scope}"),
            None,
        )
        .await?;

        self.ensure_fgap_permissions(&client, spiffe_id).await?;
        Ok(())
    }

    /// Removes everything `ensure_sandbox` created. Missing objects are not errors.
    pub async fn delete_sandbox(&self, spiffe_id: &str) -> Result<(), String> {
        if let Some(scope) = self.scope_uuid(spiffe_id).await? {
            if let Some(gateway) = self.client_uuid(&self.config.gateway_client_id).await? {
                self.admin_allow_missing(
                    Method::DELETE,
                    &format!("/clients/{gateway}/default-client-scopes/{scope}"),
                )
                .await?;
            }
            self.admin_allow_missing(Method::DELETE, &format!("/client-scopes/{scope}"))
                .await?;
        }
        if let Some(client) = self.client_uuid(spiffe_id).await? {
            self.admin_allow_missing(Method::DELETE, &format!("/clients/{client}"))
                .await?;
        }
        Ok(())
    }

    async fn ensure_audience_scope(&self, spiffe_id: &str) -> Result<String, String> {
        let scope = match self.scope_uuid(spiffe_id).await? {
            Some(uuid) => uuid,
            None => {
                let body = json!({
                    "name": spiffe_id,
                    "protocol": "openid-connect",
                    "attributes": {"include.in.token.scope": "false"},
                });
                self.admin(Method::POST, "/client-scopes", Some(&body))
                    .await?;
                self.scope_uuid(spiffe_id)
                    .await?
                    .ok_or_else(|| format!("client scope {spiffe_id} missing after create"))?
            }
        };
        let mappers = self
            .admin(
                Method::GET,
                &format!("/client-scopes/{scope}/protocol-mappers/models"),
                None,
            )
            .await?;
        let has_mapper = mappers.as_array().is_some_and(|list| {
            list.iter()
                .any(|m| m["config"]["included.client.audience"] == spiffe_id)
        });
        if !has_mapper {
            let mapper = json!({
                "name": "sandbox-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": spiffe_id,
                    "access.token.claim": "true",
                    "introspection.token.claim": "true",
                },
            });
            self.admin(
                Method::POST,
                &format!("/client-scopes/{scope}/protocol-mappers/models"),
                Some(&mapper),
            )
            .await?;
        }
        Ok(scope)
    }

    /// Configures FGAP v1 token-exchange permissions so this sandbox client
    /// can exchange tokens to each configured audience client.
    ///
    /// When the `admin-fine-grained-authz:v1` feature is active on the realm,
    /// `standard.token.exchange.enabled` is ignored; permissions must be set
    /// explicitly on the realm-management authorization server.
    async fn ensure_fgap_permissions(
        &self,
        sandbox_uuid: &str,
        _spiffe_id: &str,
    ) -> Result<(), String> {
        if self.config.audience_clients.is_empty() {
            return Ok(());
        }

        let realm_mgmt = self
            .client_uuid("realm-management")
            .await?
            .ok_or("realm-management client not found")?;

        let tx_scope_id = self.token_exchange_scope_id(&realm_mgmt).await?;
        let tx_scope_id = match tx_scope_id {
            Some(id) => id,
            None => return Ok(()),
        };

        for audience_client_id in &self.config.audience_clients {
            let audience_uuid = match self.client_uuid(audience_client_id).await? {
                Some(uuid) => uuid,
                None => continue,
            };

            self.admin(
                Method::PUT,
                &format!("/clients/{audience_uuid}/management/permissions"),
                Some(&json!({"enabled": true})),
            )
            .await?;

            let mgmt_info = self
                .admin(
                    Method::GET,
                    &format!("/clients/{audience_uuid}/management/permissions"),
                    None,
                )
                .await?;
            let tx_perm_id = mgmt_info["scopePermissions"]["token-exchange"]
                .as_str()
                .ok_or_else(|| {
                    format!("no token-exchange permission on audience {audience_client_id}")
                })?
                .to_string();
            let resource_id = mgmt_info["resource"]
                .as_str()
                .unwrap_or("")
                .to_string();

            let policy_name = format!("sandbox-exchange-{}", &sandbox_uuid[..8.min(sandbox_uuid.len())]);
            let policy_id = self
                .ensure_client_policy(&realm_mgmt, &policy_name, sandbox_uuid)
                .await?;

            let perm_body = json!({
                "id": tx_perm_id,
                "name": format!("token-exchange.permission.client.{audience_uuid}"),
                "type": "scope",
                "logic": "POSITIVE",
                "decisionStrategy": "AFFIRMATIVE",
                "resources": [resource_id],
                "scopes": [tx_scope_id],
                "policies": [policy_id],
            });
            self.admin(
                Method::PUT,
                &format!(
                    "/clients/{realm_mgmt}/authz/resource-server/permission/scope/{tx_perm_id}"
                ),
                Some(&perm_body),
            )
            .await?;
        }
        Ok(())
    }

    async fn token_exchange_scope_id(
        &self,
        realm_mgmt_uuid: &str,
    ) -> Result<Option<String>, String> {
        let scopes = self
            .admin(
                Method::GET,
                &format!(
                    "/clients/{realm_mgmt_uuid}/authz/resource-server/scope?name=token-exchange"
                ),
                None,
            )
            .await?;
        Ok(scopes
            .as_array()
            .and_then(|list| list.first())
            .and_then(|s| s["id"].as_str())
            .map(str::to_string))
    }

    async fn ensure_client_policy(
        &self,
        realm_mgmt_uuid: &str,
        policy_name: &str,
        client_uuid: &str,
    ) -> Result<String, String> {
        let body = json!({
            "name": policy_name,
            "type": "client",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "clients": [client_uuid],
        });
        let result = self
            .admin(
                Method::POST,
                &format!("/clients/{realm_mgmt_uuid}/authz/resource-server/policy/client"),
                Some(&body),
            )
            .await;
        match result {
            Ok(val) if val["id"].is_string() => {
                Ok(val["id"].as_str().unwrap().to_string())
            }
            Ok(_) | Err(_) => {
                let existing = self
                    .admin(
                        Method::GET,
                        &format!(
                            "/clients/{realm_mgmt_uuid}/authz/resource-server/policy?name={}",
                            urlencode(policy_name)
                        ),
                        None,
                    )
                    .await?;
                existing
                    .as_array()
                    .and_then(|list| list.first())
                    .and_then(|p| p["id"].as_str())
                    .map(str::to_string)
                    .ok_or_else(|| format!("failed to create or find policy {policy_name}"))
            }
        }
    }

    async fn client_uuid(&self, client_id: &str) -> Result<Option<String>, String> {
        let path = format!("/clients?clientId={}&first=0&max=2", urlencode(client_id));
        let list = self.admin(Method::GET, &path, None).await?;
        Ok(list
            .as_array()
            .and_then(|items| items.iter().find(|c| c["clientId"] == client_id))
            .and_then(|c| c["id"].as_str())
            .map(str::to_string))
    }

    async fn scope_uuid(&self, name: &str) -> Result<Option<String>, String> {
        let list = self.admin(Method::GET, "/client-scopes", None).await?;
        Ok(list
            .as_array()
            .and_then(|items| items.iter().find(|s| s["name"] == name))
            .and_then(|s| s["id"].as_str())
            .map(str::to_string))
    }

    async fn admin_allow_missing(&self, method: Method, path: &str) -> Result<(), String> {
        match self.admin(method, path, None).await {
            Ok(_) => Ok(()),
            Err(e) if e.contains("status 404") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn admin(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        let token = self.access_token().await?;
        let url = format!(
            "{}/admin/realms/{}{path}",
            self.config.base_url.trim_end_matches('/'),
            self.config.realm
        );
        let mut request = self.http.request(method.clone(), &url).bearer_auth(token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("keycloak {method} {path}: {e}"))?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            *self.token.lock().await = None;
        }
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "keycloak {method} {path}: status {}: {}",
                status.as_u16(),
                text.chars().take(300).collect::<String>()
            ));
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| format!("keycloak {method} {path}: bad JSON: {e}"))
    }

    async fn access_token(&self) -> Result<String, String> {
        let mut cached = self.token.lock().await;
        if let Some((token, expires)) = cached.as_ref()
            && Instant::now() + Duration::from_secs(30) < *expires
        {
            return Ok(token.clone());
        }
        let url = format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.config.base_url.trim_end_matches('/'),
            self.config.realm
        );
        let response = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("keycloak token request: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "keycloak token request failed: status {}",
                status.as_u16()
            ));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| format!("keycloak token response: {e}"))?;
        *cached = Some((
            token.access_token.clone(),
            Instant::now() + Duration::from_secs(token.expires_in),
        ));
        Ok(token.access_token)
    }
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod mock {
    //! In-memory stand-in for the subset of the Keycloak admin REST API this crate uses.

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{Path, Query, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{delete, get, post, put};
    use axum::{Form, Json};
    use serde_json::{Value, json};

    #[derive(Default)]
    pub struct Realm {
        pub token_requests: Vec<HashMap<String, String>>,
        pub clients: HashMap<String, Value>,
        pub client_updates: usize,
        pub scopes: HashMap<String, Value>,
        pub mappers: HashMap<String, Vec<Value>>,
        pub default_scopes: HashMap<String, Vec<String>>,
        next_id: usize,
    }

    impl Realm {
        fn id(&mut self, prefix: &str) -> String {
            self.next_id += 1;
            format!("{prefix}-{}", self.next_id)
        }
        pub fn client_by_client_id(&self, client_id: &str) -> Option<(String, Value)> {
            self.clients
                .iter()
                .find(|(_, c)| c["clientId"] == client_id)
                .map(|(id, c)| (id.clone(), c.clone()))
        }
        pub fn scope_by_name(&self, name: &str) -> Option<(String, Value)> {
            self.scopes
                .iter()
                .find(|(_, s)| s["name"] == name)
                .map(|(id, s)| (id.clone(), s.clone()))
        }
        pub fn add_client(&mut self, client_id: &str) -> String {
            let id = self.id("client");
            self.clients
                .insert(id.clone(), json!({"id": id, "clientId": client_id}));
            id
        }
        pub fn add_scope(&mut self, name: &str) -> String {
            let id = self.id("scope");
            self.scopes
                .insert(id.clone(), json!({"id": id, "name": name}));
            id
        }
    }

    pub type Shared = Arc<Mutex<Realm>>;

    async fn token(
        State(s): State<Shared>,
        Form(form): Form<HashMap<String, String>>,
    ) -> impl IntoResponse {
        let ok = form.get("client_secret").map(String::as_str) == Some("secret");
        s.lock().unwrap().token_requests.push(form);
        if ok {
            (
                StatusCode::OK,
                Json(json!({"access_token": "admin-token", "expires_in": 300})),
            )
                .into_response()
        } else {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized_client"})),
            )
                .into_response()
        }
    }

    async fn list_clients(
        State(s): State<Shared>,
        Query(q): Query<HashMap<String, String>>,
    ) -> Json<Value> {
        let s = s.lock().unwrap();
        let wanted = q.get("clientId").cloned().unwrap_or_default();
        Json(Value::Array(
            s.clients
                .values()
                .filter(|c| c["clientId"] == wanted.as_str())
                .cloned()
                .collect(),
        ))
    }

    async fn create_client(State(s): State<Shared>, Json(mut body): Json<Value>) -> StatusCode {
        let mut s = s.lock().unwrap();
        let id = s.id("client");
        body["id"] = json!(id);
        s.clients.insert(id, body);
        StatusCode::CREATED
    }

    async fn update_client(
        State(s): State<Shared>,
        Path((_, id)): Path<(String, String)>,
        Json(mut body): Json<Value>,
    ) -> StatusCode {
        let mut s = s.lock().unwrap();
        if !s.clients.contains_key(&id) {
            return StatusCode::NOT_FOUND;
        }
        body["id"] = json!(id);
        s.clients.insert(id, body);
        s.client_updates += 1;
        StatusCode::NO_CONTENT
    }

    async fn delete_client(
        State(s): State<Shared>,
        Path((_, id)): Path<(String, String)>,
    ) -> StatusCode {
        if s.lock().unwrap().clients.remove(&id).is_some() {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }

    async fn list_scopes(State(s): State<Shared>) -> Json<Value> {
        Json(Value::Array(
            s.lock().unwrap().scopes.values().cloned().collect(),
        ))
    }

    async fn create_scope(State(s): State<Shared>, Json(mut body): Json<Value>) -> StatusCode {
        let mut s = s.lock().unwrap();
        let id = s.id("scope");
        body["id"] = json!(id);
        s.scopes.insert(id, body);
        StatusCode::CREATED
    }

    async fn delete_scope(
        State(s): State<Shared>,
        Path((_, id)): Path<(String, String)>,
    ) -> StatusCode {
        if s.lock().unwrap().scopes.remove(&id).is_some() {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }

    async fn list_mappers(
        State(s): State<Shared>,
        Path((_, id)): Path<(String, String)>,
    ) -> Json<Value> {
        Json(Value::Array(
            s.lock()
                .unwrap()
                .mappers
                .get(&id)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    async fn create_mapper(
        State(s): State<Shared>,
        Path((_, id)): Path<(String, String)>,
        Json(body): Json<Value>,
    ) -> StatusCode {
        s.lock().unwrap().mappers.entry(id).or_default().push(body);
        StatusCode::CREATED
    }

    async fn add_default_scope(
        State(s): State<Shared>,
        Path((_, client, scope)): Path<(String, String, String)>,
    ) -> StatusCode {
        let mut s = s.lock().unwrap();
        let scopes = s.default_scopes.entry(client).or_default();
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
        StatusCode::NO_CONTENT
    }

    async fn remove_default_scope(
        State(s): State<Shared>,
        Path((_, client, scope)): Path<(String, String, String)>,
    ) -> StatusCode {
        let mut s = s.lock().unwrap();
        let scopes = s.default_scopes.entry(client).or_default();
        let before = scopes.len();
        scopes.retain(|x| x != &scope);
        if scopes.len() < before {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }

    /// Starts the mock and returns its base URL and shared state.
    pub async fn start() -> (String, Shared) {
        let state: Shared = Arc::default();
        let admin = "/admin/realms/{realm}";
        let app = Router::new()
            .route("/realms/{realm}/protocol/openid-connect/token", post(token))
            .route(
                &format!("{admin}/clients"),
                get(list_clients).post(create_client),
            )
            .route(
                &format!("{admin}/clients/{{id}}"),
                put(update_client).delete(delete_client),
            )
            .route(
                &format!("{admin}/client-scopes"),
                get(list_scopes).post(create_scope),
            )
            .route(
                &format!("{admin}/client-scopes/{{id}}"),
                delete(delete_scope),
            )
            .route(
                &format!("{admin}/client-scopes/{{id}}/protocol-mappers/models"),
                get(list_mappers).post(create_mapper),
            )
            .route(
                &format!("{admin}/clients/{{client}}/default-client-scopes/{{scope}}"),
                put(add_default_scope).delete(remove_default_scope),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SANDBOX: &str = "spiffe://openshell.local/openshell/sandbox/9c4daea2";
    const GATEWAY: &str = "spiffe://openshell.local/ns/openshell-e2e/sa/openshell";

    async fn setup() -> (KeycloakAdmin, mock::Shared) {
        let (url, state) = mock::start().await;
        {
            let mut realm = state.lock().unwrap();
            realm.add_client(GATEWAY);
            realm.add_scope("alpha-svc");
        }
        let admin = KeycloakAdmin::new(KeycloakConfig {
            base_url: url,
            realm: "openshell".to_string(),
            client_id: "registrar".to_string(),
            client_secret: "secret".to_string(),
            identity_provider: "spiffe".to_string(),
            gateway_client_id: GATEWAY.to_string(),
            default_scopes: vec!["alpha-svc".to_string()],
            audience_clients: vec![],
        });
        (admin, state)
    }

    #[tokio::test]
    async fn ensure_sandbox_creates_federated_client() {
        let (admin, state) = setup().await;
        admin.ensure_sandbox(SANDBOX).await.unwrap();

        let realm = state.lock().unwrap();
        let (_, client) = realm.client_by_client_id(SANDBOX).expect("sandbox client");
        assert_eq!(client["clientAuthenticatorType"], "federated-jwt");
        assert_eq!(client["publicClient"], false);
        assert_eq!(client["attributes"]["jwt.credential.issuer"], "spiffe");
        assert_eq!(client["attributes"]["jwt.credential.sub"], SANDBOX);
        assert_eq!(
            client["attributes"]["standard.token.exchange.enabled"],
            "true"
        );
    }

    #[tokio::test]
    async fn ensure_sandbox_attaches_target_scope_and_gateway_audience() {
        let (admin, state) = setup().await;
        admin.ensure_sandbox(SANDBOX).await.unwrap();

        let realm = state.lock().unwrap();
        let (sandbox_id, _) = realm.client_by_client_id(SANDBOX).unwrap();
        let (target_scope, _) = realm.scope_by_name("alpha-svc").unwrap();
        assert!(realm.default_scopes[&sandbox_id].contains(&target_scope));

        let (audience_scope, _) = realm
            .scope_by_name(SANDBOX)
            .expect("sandbox audience scope");
        let mapper = &realm.mappers[&audience_scope][0];
        assert_eq!(mapper["protocolMapper"], "oidc-audience-mapper");
        assert_eq!(mapper["config"]["included.client.audience"], SANDBOX);
        assert_eq!(mapper["config"]["access.token.claim"], "true");

        let (gateway_id, _) = realm.client_by_client_id(GATEWAY).unwrap();
        assert!(realm.default_scopes[&gateway_id].contains(&audience_scope));
    }

    #[tokio::test]
    async fn ensure_sandbox_is_idempotent() {
        let (admin, state) = setup().await;
        admin.ensure_sandbox(SANDBOX).await.unwrap();
        admin.ensure_sandbox(SANDBOX).await.unwrap();

        let realm = state.lock().unwrap();
        let sandbox_clients = realm
            .clients
            .values()
            .filter(|c| c["clientId"] == SANDBOX)
            .count();
        let audience_scopes = realm
            .scopes
            .values()
            .filter(|s| s["name"] == SANDBOX)
            .count();
        let (scope_id, _) = realm.scope_by_name(SANDBOX).unwrap();
        assert_eq!(sandbox_clients, 1);
        assert_eq!(audience_scopes, 1);
        assert_eq!(realm.mappers[&scope_id].len(), 1);
        assert_eq!(
            realm.client_updates, 1,
            "second ensure updates the existing client"
        );
    }

    #[tokio::test]
    async fn admin_token_uses_client_credentials_and_is_cached() {
        let (admin, state) = setup().await;
        admin.ensure_sandbox(SANDBOX).await.unwrap();
        admin.delete_sandbox(SANDBOX).await.unwrap();

        let realm = state.lock().unwrap();
        assert_eq!(realm.token_requests.len(), 1);
        let form = &realm.token_requests[0];
        assert_eq!(form["grant_type"], "client_credentials");
        assert_eq!(form["client_id"], "registrar");
    }

    #[tokio::test]
    async fn delete_sandbox_removes_client_scope_and_gateway_link() {
        let (admin, state) = setup().await;
        admin.ensure_sandbox(SANDBOX).await.unwrap();
        admin.delete_sandbox(SANDBOX).await.unwrap();

        let realm = state.lock().unwrap();
        assert!(realm.client_by_client_id(SANDBOX).is_none());
        assert!(realm.scope_by_name(SANDBOX).is_none());
        let (gateway_id, _) = realm.client_by_client_id(GATEWAY).unwrap();
        assert!(realm.default_scopes[&gateway_id].is_empty());
        assert!(
            realm.client_by_client_id(GATEWAY).is_some(),
            "gateway client kept"
        );
    }

    #[tokio::test]
    async fn delete_unknown_sandbox_succeeds() {
        let (admin, _) = setup().await;
        admin.delete_sandbox(SANDBOX).await.unwrap();
    }

    #[tokio::test]
    async fn missing_default_scope_is_an_error() {
        let (admin, state) = setup().await;
        state.lock().unwrap().scopes.clear();
        let err = admin.ensure_sandbox(SANDBOX).await.unwrap_err();
        assert!(err.contains("alpha-svc"), "{err}");
    }

    #[tokio::test]
    async fn rejected_admin_credentials_surface_status() {
        let (url, _) = mock::start().await;
        let admin = KeycloakAdmin::new(KeycloakConfig {
            base_url: url,
            realm: "openshell".to_string(),
            client_id: "registrar".to_string(),
            client_secret: "wrong".to_string(),
            identity_provider: "spiffe".to_string(),
            gateway_client_id: GATEWAY.to_string(),
            default_scopes: vec![],
            audience_clients: vec![],
        });
        let err = admin.ensure_sandbox(SANDBOX).await.unwrap_err();
        assert!(err.contains("401"), "{err}");
    }
}
