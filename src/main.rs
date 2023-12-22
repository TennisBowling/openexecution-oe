mod types;
use std::{sync::Arc, time::Duration, error::Error, fs::OpenOptions, sync::Mutex as StdMutex};
use std::io::Write;
use axum::headers::authorization::Bearer;
use serde::{Serialize, Deserialize};
use types::*;
use jsonwebtoken::{self, Validation};
use axum::{
    self, extract::DefaultBodyLimit, http::StatusCode, response::IntoResponse,
    Router,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::TypedHeader,
    headers::Authorization,
};
use reqwest;
use tokio::sync::{RwLock, Mutex};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use futures::{sink::SinkExt, stream::StreamExt};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};



const DEFAULT_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    /// issued-at claim. Represented as seconds passed since UNIX_EPOCH.
    iat: i64,
}


#[inline(always)]
fn make_jwt(jwt_secret: &Arc<jsonwebtoken::EncodingKey>, timestamp: &i64) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(DEFAULT_ALGORITHM),
        &Claims {
            iat: timestamp.to_owned(),
        },
        &jwt_secret,
    )
    .unwrap()
}

#[inline(always)]
async fn make_auth_request(
    jwt_secret: &Arc<jsonwebtoken::EncodingKey>,
    node: &Arc<Node>,
    payload: String,
) -> Result<String, Box<dyn Error>> {
    let jwt = make_jwt(jwt_secret, &chrono::Utc::now().timestamp());

    Ok(node
        .client
        .post(&node.url)
        .header("Authorization", format!("Bearer {}", jwt))
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await?
        .text()
        .await?)
}

#[inline(always)]
async fn make_unauth_request(node: &Arc<Node>, payload: String) -> Result<String, Box<dyn Error>> {
    Ok(node
        .client
        .post(&node.url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await?
        .text()
        .await?)
}

#[inline(always)]
fn make_syncing_string(id: &u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{},"result":{{"payloadStatus":{{"status":"SYNCING","latestValidHash":null,"validationError":null}},"payloadId":null}}}}"#,
        id
    )
}

#[inline(always)]
fn extract_prefix(input: &str) -> &str {
    if let Some(index) = input.find('_') {
        &input[..=index]
    } else {
        input
    }
}

#[inline(always)]
async fn handle_client_fcu(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // can be either fcUV1 or fcUV2, we dont care encode it as fcUV2
    let fcu = match serde_json::from_str::<forkchoiceUpdatedV2>(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse fcU JSON from client: {}", e);
            return Err(Box::new(e));
        }
    };

    if fcu.params.1.is_some() {
        // client wants to build a block
        tracing::debug!("Client wants to build a block");

        // we must check if the fcu is the same as the last legitimate fcu
        // we have to temporarily remove the payloadAttributes and the id
        let mut fcu_no_payload = fcu.clone();
        fcu_no_payload.params.1 = None;
        fcu_no_payload.id = 0;

        let last_legitimate_fcu = state.last_legitimate_fcu.read().await;
        if let Some(last_fcu) = &*last_legitimate_fcu {
            if last_fcu.req == fcu_no_payload {
                // we can just forward this request to the node
                let resp =
                    make_auth_request(&state.jwt_encoding_secret, &state.auth_node, body.to_owned()).await?;
                return Ok(resp);
            } else {
                // return an error since we can't pass a blockbuild request if they have a weird fcu
                let resp = make_syncing_string(&fcu.id);
                return Ok(resp);
            }
        }
    }

    // try to get fcu from db 5 times, once we do, return the response
    // implem a 250ms delay between each try
    let mut db_key = fcu.clone();
    db_key.id = 0;
    for _ in 1..5 {
        // we can try getting it from last_legitimate_fcu. try to find the request in the vec, if it's there get vec[1] for resp
        let last_legitimate_fcu = state.last_legitimate_fcu.read().await;
        if let Some(last_fcu) = &*last_legitimate_fcu {
            if last_fcu.req == db_key {
                return Ok(serde_json::to_string(&last_fcu.resp)?);
            }
        }
        // if we're here we didnt find it so just drop it
        drop(last_legitimate_fcu);

        let fcu_from_db = state
            .db
            .query_opt(
                "SELECT response FROM fcu WHERE request = $1;",
                &[&serde_json::to_string(&db_key)?],
            )
            .await;
        let fcu_from_db = match fcu_from_db {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Unable to get fcu from db: {}", e);
                return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get fcU from db: check openexecution\"}}".into());
            }
        };

        if !fcu_from_db.is_some() {
            tracing::debug!("fcu not found in db, waiting 250ms");
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }

        let fcu_from_db: String = fcu_from_db.unwrap().get(0);
        let fcu_from_db: forkchoiceUpdatedV1Response = match serde_json::from_str(&fcu_from_db) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Unable to parse fcU JSON from db: {}", e);
                return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse fcU from db: check openexecution\"}}".into());
            }
        };

        return Ok(fcu_from_db.set_id(fcu.id)?);
    }

    // if we're here it means we didn't find the fcu in the db, so just respond SYNCING
    Ok(make_syncing_string(&fcu.id))
}

#[inline(always)]
async fn handle_client_exchangeconfig(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // just try and get the config from the db
    // if we can't just return an error

    // json load the body
    let exchange_config = match serde_json::from_str::<exchangeTransitionConfigurationV1>(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse exchangeConfig JSON from client: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse exchangeConfig body request JSON\"}}".into());
        }
    };

    // get the config from the db
    let config_from_db = state
        .db
        .query_opt("SELECT response FROM exchangeconfig;", &[])
        .await;

    let config_from_db = match config_from_db {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to get exchangeConfig from db: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get exchangeConfig from db: check openexecution\"}}".into());
        }
    };

    if !config_from_db.is_some() {
        tracing::error!("exchangeConfig not found in db");
        return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get exchangeConfig from db: check openexecution\"}}".into());
    }

    let config_from_db: String = config_from_db.unwrap().get(0);

    // parse the config from the db
    let config_from_db = match serde_json::from_str::<exchangeTransitionConfigurationV1>(
        &config_from_db,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse exchangeConfig JSON from db: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse exchangeConfig from db: check openexecution\"}}".into());
        }
    };

    // set id and return
    Ok(config_from_db.set_id(exchange_config.id)?)
}

#[inline(always)]
async fn handle_client_newpayload(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // for newPayload, we try to find a response in the db. if we don't we can forward the request to the auth node and save the response in the db only if the response is syncing

    // json load the body
    let new_payload = match serde_json::from_str::<newPayloadV2>(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse newPayload JSON from client: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse newPayload body request JSON\"}}".into());
        }
    };

    // get the payload from the db
    let payload_from_db = state
        .db
        .query_opt(
            "SELECT response FROM newpayload WHERE request = $1;",
            &[&new_payload.params.get(0).unwrap().blockHash.to_string()],
        )
        .await;

    let payload_from_db = match payload_from_db {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to get newPayload from db: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get newPayload from db: check openexecution\"}}".into());
        }
    };

    if !payload_from_db.is_some() {
        // we didn't find the payload in the db, so we forward the request to the auth node
        let resp = make_auth_request(&state.jwt_encoding_secret, &state.auth_node, body.to_owned()).await?;
        let resp_json: newPayloadV1Response = serde_json::from_str(&resp)?;

        // if the response is syncing, we save it in the db

        match resp_json.result.status {
            ExecutionStatus::VALID => {
                // save the response in the db
                let resp_json_fordb = resp_json.clone().to_db()?;
                state.db.execute("INSERT INTO newpayload (request, response) VALUES ($1, $2) ON CONFLICT (request) DO UPDATE SET response = $2;;", &[&new_payload.params.get(0).unwrap().blockHash.to_string(), &resp_json_fordb]).await?;
            }
            _ => {} // we dont save the response in the db
        }

        return Ok(resp_json.set_id(new_payload.id)?);
    }

    // we found the payload in the db, so we just return it
    let payload_from_db: String = payload_from_db.unwrap().get(0);
    let payload_from_db: newPayloadV1Response = serde_json::from_str(&payload_from_db)?;

    Ok(payload_from_db.set_id(new_payload.id)?)
}

#[inline(always)]
async fn handle_passto_auth(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // we can just pass these requests to the auth node

    Ok(make_auth_request(&state.jwt_encoding_secret, &state.auth_node, body.to_owned()).await?)
}

#[inline(always)]
async fn handle_passto_unauth(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // we can just pass these requests to the unauth node

    Ok(make_unauth_request(&state.unauth_node, body.to_owned()).await?)
}

#[inline(always)]
async fn handle_canonical_fcu(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // load json
    let fcu = serde_json::from_str::<forkchoiceUpdatedV2>(body)?;

    // make request to auth node
    let resp = make_auth_request(&state.jwt_encoding_secret, &state.auth_node, body.to_owned()).await?;

    // load it into a json
    let resp_json = serde_json::from_str::<forkchoiceUpdatedV1Response>(&resp);

    if let Err(e) = resp_json {
        tracing::error!(
            "Unable to parse forkchoiceUpdated response JSON from auth node: {}",
            e
        );
        let mut file = OpenOptions::new().append(true).open("error.log").unwrap();
        let _ = writeln!(
            file,
            "{}",
            format!("fcu req: {}\nfcu resp: {}\n\n", body, resp)
        );
        return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse forkchoiceUpdated response JSON from auth node\"}}".into());
    }

    // insert into db with the headblockhash as the key
    let resp_json = resp_json.unwrap();
    let mut resp_fordb = resp_json.clone();
    resp_fordb.id = 0;
    let mut req_fordb = fcu.clone();
    req_fordb.id = 0;

    match resp_json.result.payloadStatus.status {
        ExecutionStatus::VALID => {
            // we update the last_legitimate_fcu
            let mut last_legitimate_fcu = state.last_legitimate_fcu.write().await;
            *last_legitimate_fcu = Some(fcu_pair {
                req: req_fordb.clone(),
                resp: resp_fordb.clone(),
            });
            drop(last_legitimate_fcu);
        }
        ExecutionStatus::INVALID => {}
        ExecutionStatus::SYNCING => {}
        ExecutionStatus::ACCEPTED => {}
        ExecutionStatus::INVALID_BLOCK_HASH => {}
    }

    state.db.execute("INSERT INTO fcu (request, response) VALUES ($1, $2) ON CONFLICT (request) DO UPDATE SET response = $2;;", &[&serde_json::to_string(&req_fordb)?, &serde_json::to_string(&resp_fordb)?]).await?;

    Ok(resp)
}

#[inline(always)]
async fn handle_canonical_newpayload(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // load json
    let new_payload = match serde_json::from_str::<newPayloadV2>(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse newPayload from canonical node JSON: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse newPayload from canonical node body request JSON\"}}".into());
        }
    };

    // so the non-canonical CL might've already stored the response in the db so just try to get that
    let payload_from_db = state
        .db
        .query_opt(
            "SELECT response FROM newpayload WHERE request = $1;",
            &[&new_payload.params.get(0).unwrap().blockHash.to_string()],
        )
        .await;

    let payload_from_db = match payload_from_db {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to get newPayload from db: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get newPayload from db: check openexecution\"}}".into());
        }
    };

    if !payload_from_db.is_some() {
        // we didn't find the payload in the db, so we forward the request to the auth node and save the resp in the db
        let resp = make_auth_request(&state.jwt_encoding_secret, &state.auth_node, body.to_owned()).await?;
        let resp_json: newPayloadV1Response = serde_json::from_str(&resp)?;

        // put in db
        let resp_json_fordb = resp_json.clone().to_db()?;
        state.db.execute("INSERT INTO newpayload (request, response) VALUES ($1, $2) ON CONFLICT (request) DO UPDATE SET response = $2;",
        &[&new_payload.params.get(0).unwrap().blockHash.to_string(), &resp_json_fordb]).await?;

        return Ok(resp);
    }

    // if we're here that means we have a response in the db, so we just load the json set the id and return

    let payload_from_db: String = payload_from_db.unwrap().get(0);
    let payload_from_db: newPayloadV1Response = serde_json::from_str(&payload_from_db)?;

    Ok(payload_from_db.set_id(new_payload.id)?)
}

#[inline(always)]
async fn handle_canonical_exchangeconfig(
    body: &str,
    state: &State,
) -> Result<String, Box<dyn Error>> {
    // we have to send the exchange config to the auth node and then store the response in the db, always overwriting whatevers in the db

    let resp = make_auth_request(&state.jwt_encoding_secret, &state.auth_node, body.to_owned()).await?;
    let resp_json = serde_json::from_str::<exchangeTransitionConfigurationV1>(&resp);

    if let Err(e) = resp_json {
        tracing::error!(
            "Unable to parse exchange config from canonical node JSON: {}",
            e
        );
        tracing::error!("raw body: {}", body);
        tracing::info!("resp: {}", resp);
        return Ok(resp);
    }

    // put in db
    let resp_json = resp_json.unwrap();
    let resp_json_fordb = resp_json.clone().to_db()?;

    state.db.execute("DELETE FROM exchangeconfig;", &[]).await?;
    state
        .db
        .execute(
            "INSERT INTO exchangeconfig (response) VALUES ($1);",
            &[&resp_json_fordb],
        )
        .await?;

    Ok(resp)
}

#[inline(always)]
async fn handle_client_cl(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    body: String,
) -> impl IntoResponse {
    // load json into a Value
    let json_body: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse JSON from client: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot parse client body request JSON\"}}",
            ).into_response();
        }
    };

    // match the method to the correct handler

    let method = match json_body.get("method") {
        Some(v) => v,
        None => {
            tracing::error!("Unable to get method from client request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot get method from client body request JSON\"}}",
            ).into_response();
        }
    };

    let method = match method.as_str() {
        Some(v) => v,
        None => {
            tracing::error!("Unable to parse method from client request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot parse method from client body request JSON\"}}",
            ).into_response();
        }
    };

    let method_semi = extract_prefix(method);

    match method_semi {
        "engine_" => match method {
            "engine_forkchoiceUpdatedV1" | "engine_forkchoiceUpdatedV2" => {
                match handle_client_fcu(&body, &state).await {
                    Ok(v) => return (StatusCode::OK, v).into_response(),
                    Err(e) => {
                        tracing::error!(
                            "Unable to handle client fcU request: {}; Body: {}",
                            e,
                            body
                        );
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                        )
                            .into_response();
                    }
                }
            }

            "engine_exchangeTransitionConfigurationV1" => {
                match handle_client_exchangeconfig(&body, &state).await {
                    Ok(v) => return (StatusCode::OK, v).into_response(),
                    Err(e) => {
                        tracing::error!(
                            "Unable to handle client exchangeConfig request: {}; Body: {}",
                            e,
                            body
                        );
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                        )
                            .into_response();
                    }
                }
            }

            "engine_newPayloadV1" | "engine_newPayloadV2" => {
                match handle_client_newpayload(&body, &state).await {
                    Ok(v) => return (StatusCode::OK, v).into_response(),
                    Err(e) => {
                        tracing::error!(
                            "Unable to handle client newPayload request: {}; Body: {}",
                            e,
                            body
                        );
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                        )
                            .into_response();
                    }
                }
            }

            "engine_getPayloadV1"
            | "engine_getPayloadV2"
            | "engine_getPayloadBodiesByHashV1"
            | "engine_getPayloadBodiesByRangeV1"
            | "engine_exchangeCapabilities" => match handle_passto_auth(&body, &state).await {
                Ok(v) => return (StatusCode::OK, v).into_response(),
                Err(e) => {
                    tracing::error!(
                        "Unable to handle client {} request: {}; Body: {}",
                        method,
                        e,
                        body
                    );
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                    )
                        .into_response();
                }
            },

            _ => {
                tracing::error!("Unable to match engine method from client request");
                return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "{\"error\":{\"code\":-32000,\"message\":\"Cannot match engine method from body request JSON\"}}",
                    ).into_response();
            }
        },

        "web3_" | "eth_" | "net_" => match handle_passto_unauth(&body, &state).await {
            Ok(v) => return (StatusCode::OK, v).into_response(),
            Err(e) => {
                tracing::error!(
                    "Unable to handle client {} request: {}; Body: {}",
                    method,
                    e,
                    body
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                )
                    .into_response();
            }
        },

        _ => {
            tracing::error!("Unable to match method from client request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot match method from body request JSON\"}}",
            ).into_response();
        }
    }
}

#[inline(always)]
async fn handle_canonical_cl(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    body: String,
) -> impl IntoResponse {
    // load json into a Value
    let json_body: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse JSON from canonical: {}; Body: {}", e, body);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot parse canonical body request JSON\"}}",
            ).into_response();
        }
    };

    // match the method to the correct handler

    let method = match json_body.get("method") {
        Some(v) => v,
        None => {
            tracing::error!("Unable to get method from canonical request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot get method from canonical body request JSON\"}}",
            ).into_response();
        }
    };

    let method = match method.as_str() {
        Some(v) => v,
        None => {
            tracing::error!("Unable to parse method from canonical request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot parse method from canonical body request JSON\"}}",
            ).into_response();
        }
    };

    let method_semi = extract_prefix(method);

    match method_semi {
        "engine_" => match method {
            "engine_forkchoiceUpdatedV1" | "engine_forkchoiceUpdatedV2" => {
                match handle_canonical_fcu(&body, &state).await {
                    Ok(v) => return (StatusCode::OK, v).into_response(),
                    Err(e) => {
                        tracing::error!(
                            "Unable to handle canonical fcU request: {}; Body: {}",
                            e,
                            body
                        );
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                        )
                            .into_response();
                    }
                }
            }

            "engine_exchangeTransitionConfigurationV1" => {
                match handle_canonical_exchangeconfig(&body, &state).await {
                    Ok(v) => return (StatusCode::OK, v).into_response(),
                    Err(e) => {
                        tracing::error!(
                            "Unable to handle canonical exchangeConfig request: {}; Body: {}",
                            e,
                            body
                        );
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                        )
                            .into_response();
                    }
                }
            }

            "engine_newPayloadV1" | "engine_newPayloadV2" => {
                match handle_canonical_newpayload(&body, &state).await {
                    Ok(v) => return (StatusCode::OK, v).into_response(),
                    Err(e) => {
                        tracing::error!(
                            "Unable to handle canonical newPayload request: {}; Body: {}",
                            e,
                            body
                        );
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                        )
                            .into_response();
                    }
                }
            }

            "engine_getPayloadV1"
            | "engine_getPayloadV2"
            | "engine_getPayloadBodiesByHashV1"
            | "engine_getPayloadBodiesByRangeV1"
            | "engine_exchangeCapabilities" => match handle_passto_auth(&body, &state).await {
                Ok(v) => return (StatusCode::OK, v).into_response(),
                Err(e) => {
                    tracing::error!(
                        "Unable to handle canonical {} request: {}; Body: {}",
                        method,
                        e,
                        body
                    );
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                    )
                        .into_response();
                }
            },

            _ => {
                tracing::error!("Unable to match engine method from canonical request");
                return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "{\"error\":{\"code\":-32000,\"message\":\"Cannot match engine method from body request JSON\"}}",
                    ).into_response();
            }
        },

        "web3_" | "eth_" | "net_" => match handle_passto_unauth(&body, &state).await {
            Ok(v) => return (StatusCode::OK, v).into_response(),
            Err(e) => {
                tracing::error!(
                    "Unable to handle canonical {} request: {}; Body: {}",
                    method,
                    e,
                    body
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                )
                    .into_response();
            }
        },

        _ => {
            tracing::error!("Unable to match method from canonical request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot match method from canonical body request JSON\"}}",
            ).into_response();
        }
    }
}


// called once for the http upgrade
async fn ws_canonical_handler(
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let authorization = authorization.token();
    let authorization = authorization.replace("Bearer ", "");

    let mut validation = Validation::new(DEFAULT_ALGORITHM);
    validation.validate_exp = false;
    validation.required_spec_claims = Default::default();
    match jsonwebtoken::decode::<Claims>(&authorization, &state.jwt_decoding_secret, &validation) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to decode JWT: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot decode JWT\"}}",
            ).into_response();
        }
    };

    // we check if the canonical header is present
    // if it is, upgrade to the handle_socket_canonical

    // they have a valid jwt, let them upgrade
    ws.on_upgrade(move |socket| handle_canonical_socket(axum::extract::State(state), socket))
    
}

// called once for the http upgrade
async fn ws_client_handler(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {

    ws.on_upgrade(move |socket| handle_client_socket(axum::extract::State(state), socket))
    
}

async fn handle_canonical_socket(axum::extract::State(state): axum::extract::State<Arc<State>>, mut socket: WebSocket) {
    if !socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
        // no Error here since the only thing we can do is to close the connection.
        // If we can not send messages, there is no way to salvage the statemachine anyway.
        return;
    }

    let (tx, rx) = socket.split();
    let tx = Arc::new(Mutex::new(tx));

    // we need to continually read from the socket, and send it to the handle_canonical_cl function

    // calling return inside this means we just stop execution for that message
    rx.for_each_concurrent(None,  move |msg| {
        let state = state.clone();
        let tx = tx.clone();
        async move {
            let msg =  match msg {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Unable to read from websocket: {}", e);
                    return;
                }
            };

            let msg = match msg {
                Message::Text(v) => v,
                Message::Binary(_) => {
                    tracing::error!("Unable to read from websocket: Binary");
                    return;
                }
                Message::Ping(_) => {
                    return;
                }
                Message::Pong(_) => {
                    return;
                }
                Message::Close(_) => {
                    return;
                }
            };

            let resp = handle_canonical_cl(axum::extract::State(state), msg).await.into_response();
            let resp = String::from_utf8_lossy(&hyper::body::to_bytes(resp.into_body()).await.unwrap()).to_string();

            if !tx.lock().await.send(Message::Text(resp)).await.is_ok() {
                // no Error here since the only thing we can do is to close the connection.
                // If we can not send messages, there is no way to salvage the statemachine anyway.
                return;
            }
        }

    }).await;

}

async fn handle_client_socket(axum::extract::State(state): axum::extract::State<Arc<State>>, mut socket: WebSocket) {
    if !socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
        // no Error here since the only thing we can do is to close the connection.
        // If we can not send messages, there is no way to salvage the statemachine anyway.
        return;
    }

    let (tx, rx) = socket.split();
    let tx = Arc::new(Mutex::new(tx));

    // we need to continually read from the socket, and send it to the handle_canonical_cl function
    // calling return inside this means we just stop execution for that message

    rx.for_each_concurrent(None,  move |msg| {
        let state = state.clone();
        let tx = tx.clone();
        async move {
            let msg =  match msg {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Unable to read from websocket: {}", e);
                    return;
                }
            };

            let msg = match msg {
                Message::Text(v) => v,
                Message::Binary(_) => {
                    tracing::error!("Unable to read from websocket: Binary");
                    return;
                }
                Message::Ping(_) => {
                    return;
                }
                Message::Pong(_) => {
                    return;
                }
                Message::Close(_) => {
                    return;
                }
            };

            let resp = handle_canonical_cl(axum::extract::State(state), msg).await.into_response();
            let resp = String::from_utf8_lossy(&hyper::body::to_bytes(resp.into_body()).await.unwrap()).to_string();

            if !tx.lock().await.send(Message::Text(resp)).await.is_ok() {
                // no Error here since the only thing we can do is to close the connection.
                // If we can not send messages, there is no way to salvage the statemachine anyway.
                return;
            }
        }

    }).await;

}

#[tokio::main]
async fn main() {
    let matches = clap::App::new("openexecution")
        .version("0.1.0")
        .author("TennisBowling <tennisbowling@tennisbowling.com>")
        .about(
            "OpenExecution is a program that lets you control multiple CL's with one canonical CL",
        )
        .setting(clap::AppSettings::ColoredHelp)
        .long_version(
            "OpenExecution version 0.1.0 by TennisBowling <tennisbowling@tennisbowling.com>",
        )
        .arg(
            clap::Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .takes_value(true)
                .default_value("7000"),
        )
        .arg(
            clap::Arg::with_name("jwt-secret")
                .long("jwt-secret")
                .value_name("JWT")
                .help("Path to JWT secret file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("listen-addr")
                .long("listen-addr")
                .value_name("LISTEN")
                .help("Address to listen on")
                .takes_value(true)
                .default_value("0.0.0.0"),
        )
        .arg(
            clap::Arg::with_name("log-level")
                .long("log-level")
                .value_name("LOG")
                .help("Log level")
                .takes_value(true)
                .default_value("info"),
        )
        .arg(
            clap::Arg::with_name("node")
                .long("node")
                .value_name("NODE")
                .help("EL node to connect to for engine_ requests")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("unauth-node")
                .long("unauth-node")
                .value_name("unauth_node")
                .help("unauth EL node to connect to (for non-engine_ requests, such as eth_ requests)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("db-host")
                .long("db-host")
                .value_name("DB host")
                .help("Database host ip")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("db-user")
                .long("db-user")
                .value_name("DB user")
                .help("Database user")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("db-pass")
                .long("db-pass")
                .value_name("DB pass")
                .help("Database password")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("db-name")
                .long("db-name")
                .value_name("DB name")
                .help("Database name")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("db-port")
                .long("db-port")
                .value_name("DB port")
                .help("Database port")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("log-file")
                .long("log-file")
                .value_name("log-path")
                .help("Path to log file")
                .takes_value(true),
        )
        .get_matches();

    let port = matches.value_of("port").unwrap();
    let jwt_secret = matches.value_of("jwt-secret").unwrap();
    let listen_addr = matches.value_of("listen-addr").unwrap();
    let log_level = matches.value_of("log-level").unwrap();
    let node = matches.value_of("node").unwrap();
    let unauth_node = matches.value_of("unauth-node").unwrap();
    let db_host = matches.value_of("db-host").unwrap().to_string();
    let db_user = matches.value_of("db-user").unwrap().to_string();
    let db_pass = matches.value_of("db-pass").unwrap().to_string();
    let db_name = matches.value_of("db-name").unwrap().to_string();
    let db_port = matches.value_of("db-port").unwrap().to_string();

    let log_level = match log_level {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    // set log level with tracing subscriber

    // if there's a log file, set it and stdout as the subscriber
    // if not, just set stdout

    match matches.value_of("log-file") {
        Some(path) => {
            let log_file = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(path);

            if let Err(e) = log_file {
                println!("Unable to open log file: {}", e);
                std::process::exit(1);
            }

            let log_file = log_file.unwrap();

            let multiwriter = MultiWriter::new(Arc::new(StdMutex::new(log_file)));

            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_max_level(log_level)  
                    .finish()
                    .with(
                        tracing_subscriber::fmt::Layer::new()
                            .with_ansi(false)
                            .with_writer(multiwriter),
                    ),
            )
            .expect("Unable to set global default subscriber")
        }
        None => tracing::subscriber::set_global_default(
            tracing_subscriber::fmt().with_max_level(log_level).finish(),
        )
        .expect("Unable to set global default subscriber"),
    };

    tracing::info!("Starting executionbackup version 1.0.2");

    let jwt_secret = std::fs::read_to_string(jwt_secret);
    if let Err(e) = jwt_secret {
        tracing::error!("Unable to read JWT secret: {}", e);
        std::process::exit(1);
    }
    let jwt_secret = jwt_secret.unwrap();

    let jwt_secret = jwt_secret.trim().to_string();

    // check if jwt_secret starts with "0x" and remove it if it does
    let jwt_secret = jwt_secret
        .strip_prefix("0x")
        .unwrap_or(&jwt_secret)
        .to_string();

    let jwt_secret = hex::decode(jwt_secret);
    if let Err(e) = jwt_secret {
        tracing::error!("Unable to decode JWT secret: {}", e);
        std::process::exit(1);
    }
    let jwt_secret = jwt_secret.unwrap();

    let jwt_encoding_secret = &jsonwebtoken::EncodingKey::from_secret(&jwt_secret);
    let jwt_decoding_secret = &jsonwebtoken::DecodingKey::from_secret(&jwt_secret);

    tracing::info!("Loaded JWT secret");

    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host={} port={} user={} password={} dbname={}",
            db_host, db_port, db_user, db_pass, db_name
        ),
        tokio_postgres::NoTls,
    )
    .await
    .expect("Unable to connect to postgres");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!("Connection error: {}", e);
        }
    });

    tracing::info!("Connected to postgres");

    // create tables if they don't exist

    client.query(
        "CREATE TABLE IF NOT EXISTS fcu (request TEXT NOT NULL UNIQUE, response TEXT NOT NULL);",
        &[],
    ).await.expect("Unable to create fcu table");

    client.query(
        "CREATE TABLE IF NOT EXISTS newpayload (request TEXT NOT NULL UNIQUE, response TEXT NOT NULL);",
        &[],
    ).await.expect("Unable to create newpayload table");

    client
        .query(
            "CREATE TABLE IF NOT EXISTS exchangeconfig (response TEXT NOT NULL);",
            &[],
        )
        .await
        .expect("Unable to create exchangeconfig table");

    // make the state
    let state = Arc::new(State {
        db: Arc::new(client),
        jwt_encoding_secret: Arc::new(jwt_encoding_secret.clone()),
        jwt_decoding_secret: Arc::new(jwt_decoding_secret.clone()),
        auth_node: Arc::new(Node {
            client: reqwest::Client::new(),
            url: node.to_string(),
        }),
        unauth_node: Arc::new(Node {
            client: reqwest::Client::new(),
            url: unauth_node.to_string(),
        }),
        last_legitimate_fcu: Arc::new(RwLock::new(None)),
    });

    let app: Router = Router::new()
        .route("/", axum::routing::post(handle_client_cl))
        .route("/", axum::routing::get(ws_client_handler))
        .route("/canonical", axum::routing::post(handle_canonical_cl))
        .route("/canonical", axum::routing::get(ws_canonical_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::default().include_headers(true)))
        .layer(DefaultBodyLimit::disable());

    let addr = format!("{}:{}", listen_addr, port).parse();
    if let Err(e) = addr {
        tracing::error!("Unable to parse listen address: {}", e);
        std::process::exit(1);
    }
    let addr = addr.unwrap();

    tracing::info!("Listening on {}", addr);

    let server = axum::Server::bind(&addr).serve(app.into_make_service());

    if let Err(e) = server.await {
        tracing::error!("Server error: {}", e);
    }
}
