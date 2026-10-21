// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use keycloak_registrar_interceptor::{
    auth::GatewayTokenVerifier, config::Config, keycloak::KeycloakAdmin, service::RegistrarService,
    spiffe::SpiffeIdTemplate, webhook,
};
use openshell_core::proto::gateway_interceptor::v1::gateway_interceptor_server::GatewayInterceptorServer;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to install rustls crypto provider")?;

    let config = Config::from_env(|key| std::env::var(key).ok())?;
    let public_key = std::fs::read(&config.gateway_public_key_file)?;
    let verifier = GatewayTokenVerifier::new(&public_key, &config.gateway_id, &config.audience)?;
    let template = SpiffeIdTemplate::new(&config.spiffe_id_template, &config.sandbox_namespace)?;
    let cert_pem = std::fs::read(&config.tls_cert_file)?;
    let key_pem = std::fs::read(&config.tls_key_file)?;
    let identity = Identity::from_pem(cert_pem.clone(), key_pem.clone());

    let keycloak = Arc::new(KeycloakAdmin::new(config.keycloak.clone()));

    let service = RegistrarService::new(
        verifier,
        config.audience.clone(),
        config.trust_domain.clone(),
        template,
        keycloak.clone(),
    );

    info!(
        listen = %config.listen_addr,
        webhook_listen = %config.webhook_listen_addr,
        gateway_id = %config.gateway_id,
        audience = %config.audience,
        realm = %config.keycloak.realm,
        "keycloak registrar interceptor starting"
    );

    let grpc_handle = tokio::spawn({
        let addr = config.listen_addr;
        async move {
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(identity))?
                .add_service(GatewayInterceptorServer::new(service))
                .serve_with_shutdown(addr, async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
        }
    });

    let webhook_handle = tokio::spawn({
        let addr = config.webhook_listen_addr;
        let kc = keycloak.clone();
        let webhook_cert = config
            .webhook_tls_cert_file
            .as_ref()
            .map(std::fs::read)
            .transpose()?
            .unwrap_or_else(|| cert_pem.clone());
        let webhook_key = config
            .webhook_tls_key_file
            .as_ref()
            .map(std::fs::read)
            .transpose()?
            .unwrap_or_else(|| key_pem.clone());
        async move {
            let app = Router::new()
                .route("/webhook/audience", post(webhook::handle_admission))
                .with_state(kc);
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
                webhook_cert,
                webhook_key,
            )
            .await?;
            info!(%addr, "webhook server listening (TLS)");
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await
        }
    });

    tokio::select! {
        r = grpc_handle => r??,
        r = webhook_handle => r??,
    }
    Ok(())
}
