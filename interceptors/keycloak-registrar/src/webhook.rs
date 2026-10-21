// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes admission webhook that auto-creates Keycloak audience clients
//! when a Service with the `openshell.ai/audience` annotation is created,
//! and removes them when the Service is deleted.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::keycloak::KeycloakAdmin;

const LABEL_KEY: &str = "openshell.ai/audience";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    pub api_version: String,
    pub kind: String,
    pub request: AdmissionRequest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    pub uid: String,
    pub operation: String,
    #[serde(default)]
    pub object: Option<Value>,
    #[serde(default)]
    pub old_object: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionResponse {
    api_version: String,
    kind: String,
    response: ResponseBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseBody {
    uid: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<ResponseStatus>,
}

#[derive(Serialize)]
struct ResponseStatus {
    message: String,
}

fn extract_audience_info(obj: &Value) -> Option<(String, String)> {
    let metadata = obj.get("metadata")?;
    let has_label = metadata
        .get("labels")
        .and_then(|l| l.get(LABEL_KEY))
        .and_then(|v| v.as_str())
        .is_some_and(|v| v == "true");
    let has_annotation = metadata
        .get("annotations")
        .and_then(|a| a.get(LABEL_KEY))
        .and_then(|v| v.as_str())
        .is_some_and(|v| v == "true");
    if !has_label && !has_annotation {
        return None;
    }
    let name = metadata.get("name")?.as_str()?.to_string();
    let namespace = metadata
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((name, namespace))
}

fn allow(uid: &str) -> AdmissionResponse {
    AdmissionResponse {
        api_version: "admission.k8s.io/v1".to_string(),
        kind: "AdmissionReview".to_string(),
        response: ResponseBody {
            uid: uid.to_string(),
            allowed: true,
            status: None,
        },
    }
}

pub async fn handle_admission(
    State(kc): State<Arc<KeycloakAdmin>>,
    Json(review): Json<AdmissionReview>,
) -> impl IntoResponse {
    let uid = review.request.uid.clone();
    let op = review.request.operation.as_str();

    match op {
        "CREATE" | "UPDATE" => {
            if let Some(obj) = &review.request.object {
                if let Some((name, namespace)) = extract_audience_info(obj) {
                    info!(%name, %namespace, "webhook: registering audience client");
                    if let Err(e) = kc.ensure_audience_client(&name, &namespace).await {
                        warn!(%name, %e, "webhook: failed to register audience client");
                    }
                    info!(%name, "webhook: syncing FGAP for existing sandboxes");
                    if let Err(e) = kc.sync_fgap_all_sandboxes().await {
                        warn!(%name, %e, "webhook: FGAP sync failed");
                    }
                }
            }
        }
        "DELETE" => {
            let obj = review
                .request
                .old_object
                .as_ref()
                .or(review.request.object.as_ref());
            if let Some(obj) = obj {
                if let Some((name, _namespace)) = extract_audience_info(obj) {
                    info!(%name, "webhook: deregistering audience client");
                    if let Err(e) = kc.delete_audience_client(&name).await {
                        warn!(%name, %e, "webhook: failed to deregister audience client");
                    }
                }
            }
        }
        _ => {}
    }

    (StatusCode::OK, Json(allow(&uid)))
}
