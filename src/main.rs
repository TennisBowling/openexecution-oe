mod types;
use std::{sync::Arc, time::Duration, error::Error};
use serde::{Serialize, Deserialize};
use types::*;
use jsonwebtoken;
use axum::{
    self,
    response::IntoResponse,
    Extension, Router, extract::DefaultBodyLimit, http::StatusCode,
};
use tokio::sync::RwLock;
use reqwest::{self};


const DEFAULT_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    /// issued-at claim. Represented as seconds passed since UNIX_EPOCH.
    iat: i64,
    /// Optional unique identifier for the CL node.
    id: String,
    /// Optional client version for the CL node.
    clv: String,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub url: String,
    pub client: reqwest::Client,
}

#[inline(always)]
fn make_jwt(jwt_secret: Arc<jsonwebtoken::EncodingKey>, timestamp: &i64) -> String {

    let claim_inst = Claims {
        iat: timestamp.to_owned(),
        id: "1".to_owned(),
        clv: "1".to_owned(),
    };

    let header = jsonwebtoken::Header::new(DEFAULT_ALGORITHM);
    jsonwebtoken::encode(&header, &claim_inst, &jwt_secret).unwrap()

}

#[inline(always)]
async fn make_auth_request(jwt_secret: &Arc<jsonwebtoken::EncodingKey>, node: &Arc<Node>, payload: String) -> Result<String, Box<dyn Error>> {
    let timestamp = chrono::Utc::now().timestamp();
    let jwt = make_jwt(jwt_secret.clone(), &timestamp);
    
    Ok(node.client
        .post(&node.url)
        .header("Authorization", jwt)
        .header("Content-Type", "application/json")
        .body(payload)
        .timeout(Duration::from_millis(2500))
        .send()
        .await?
        .text()
        .await?)

}   

#[inline(always)]
async fn make_unauth_request(node: &Arc<Node>, payload: String) -> Result<String, Box<dyn Error>> {
    Ok(node.client
        .post(&node.url)
        .header("Content-Type", "application/json")
        .body(payload)
        .timeout(Duration::from_millis(2500))
        .send()
        .await?
        .text()
        .await?)
}

#[inline(always)]
fn make_syncing_string(id: &u64) -> String {
    format!(r#"{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"payloadStatus\":{{\"status\":\"SYNCING\",\"latestValidHash\":null,\"validationError\":null}},\"payloadId\":null}}}}"#, id)
}

#[inline(always)]
fn extract_prefix(input: &str) -> &str {
    if let Some(index) = input.find('_') {
        &input[..=index]
    } else {
        input
    }
}


#[derive(Clone)]
struct State {
    db: Arc<tokio_postgres::Client>,
    jwt_secret: Arc<jsonwebtoken::EncodingKey>,
    auth_node: Arc<Node>,
    unauth_node: Arc<Node>,
    last_legitimate_fcu: Arc<RwLock<String>>,
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
    


    if fcu.params.get(0).unwrap().payloadAttributes.is_some() {
        // client wants to build a block
        tracing::debug!("Client wants to build a block");

        // we must check if the fcu is the same as the last legitimate fcu
        // we have to temporarily remove the payloadAttributes and the id
        let mut fcu_no_payload = fcu.clone();
        fcu_no_payload.params.get_mut(0).unwrap().payloadAttributes = None;
        fcu_no_payload.id = 0;
        let fcu_no_payload_string = serde_json::to_string(&fcu_no_payload).unwrap();

        let last_legitimate_fcu = state.last_legitimate_fcu.read().await;

        if *last_legitimate_fcu != fcu_no_payload_string {
            tracing::debug!("Client sent an invalid fcu with payloadAttributes, refusing to build a block");
            return Ok("{\"error\":{\"code\":-32000,\"message\":\"Cannot let you build a block with an invalid fcU\"}}".to_string());
        }

        // quick drop the lock so others can use it
        drop(last_legitimate_fcu);

        // since the fcU is the same as the last legitimate one, we can just forward this request to the node
        let resp = make_auth_request(&state.jwt_secret, &state.auth_node, body.to_owned()).await?;
        return Ok(resp);
    }

    // try to get fcu from db 5 times, once we do, return the response
    // implem a 250ms delay between each try
    let head_block_hash = fcu.params.get(0).unwrap().forkchoiceState.headBlockHash.to_string();
    for _ in 1..5 {
        let fcu_from_db = state.db.query_one("SELECT response FROM fcu WHERE request = $1", &[&head_block_hash]).await;
        let fcu_from_db = match fcu_from_db {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Unable to get fcu from db: {}", e);
                return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get fcU from db: check openexecution\"}}".into());
            }
        };

        if fcu_from_db.is_empty() {
            tracing::trace!("fcu not found in db, waiting 250ms");
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }

        let fcu_from_db: String = fcu_from_db.get(0);
        let fcu_from_db: forkchoiceUpdatedV1Response = match serde_json::from_str(&fcu_from_db) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Unable to parse fcU JSON from db: {}", e);
                return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse fcU from db: check openexecution\"}}".into());
            }
        };

        return Ok(serde_json::to_string(&fcu_from_db.set_id(fcu.id)?)?);

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
    let config_from_db = state.db.query_one("SELECT response FROM exchange_config WHERE request = '1'", &[]).await;

    let config_from_db = match config_from_db {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to get exchangeConfig from db: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get exchangeConfig from db: check openexecution\"}}".into());
        }
    };

    let config_from_db: String = config_from_db.get(0);

    // parse the config from the db
    let config_from_db = match serde_json::from_str::<exchangeTransitionConfigurationV1>(&config_from_db) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse exchangeConfig JSON from db: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot parse exchangeConfig from db: check openexecution\"}}".into());
        }
    };

    // set id and return
    Ok(serde_json::to_string(&config_from_db.set_id(exchange_config.id)?)?)
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
    let payload_from_db = state.db.query_one("SELECT response FROM newPayload WHERE request = $1", &[&new_payload.params.get(0).unwrap().blockHash.to_string()]).await;

    let payload_from_db = match payload_from_db {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to get newPayload from db: {}", e);
            return Err("{\"error\":{\"code\":-32000,\"message\":\"Cannot get newPayload from db: check openexecution\"}}".into());
        }
    };

    if payload_from_db.is_empty() {
        // we didn't find the payload in the db, so we forward the request to the auth node
        let resp = make_auth_request(&state.jwt_secret, &state.auth_node, body.to_owned()).await?;
        let resp_json: newPayloadV1Response = serde_json::from_str(&resp)?;

        // if the response is syncing, we save it in the db
        
        match resp_json.result.status {
            ExecutionStatus::VALID => {
                // save the response in the db
                state.db.execute("INSERT INTO newPayload (request, response) VALUES ($1, $2)", &[&new_payload.params.get(0).unwrap().blockHash.to_string(), &resp.to_string()]).await?;
            },
            _ => {} // we dont save the response in the db
        }

        return Ok(serde_json::to_string(&resp_json.set_id(new_payload.id)?)?);
    }

    // we found the payload in the db, so we just return it
    let payload_from_db: String = payload_from_db.get(0);
    let payload_from_db: newPayloadV1Response = serde_json::from_str(&payload_from_db)?;

    Ok(serde_json::to_string(&payload_from_db.set_id(new_payload.id)?)?)
}


#[inline(always)]
async fn handle_client_passto_auth(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // we can just pass these requests to the auth node

    Ok(make_auth_request(&state.jwt_secret, &state.auth_node, body.to_owned()).await?)

}

#[inline(always)]
async fn handle_client_passto_unauth(body: &str, state: &State) -> Result<String, Box<dyn Error>> {
    // we can just pass these requests to the unauth node

    Ok(make_unauth_request(&state.unauth_node, body.to_owned()).await?)

}



async fn handle_client_cl(body: String, Extension(state): Extension<State>) -> impl IntoResponse {
    // load json into a Value
    let json_body: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Unable to parse JSON from client: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot parse body request JSON\"}}",
            ).into_response();
        }
    };

    // match the method to the correct handler
    // just leave the actual matches todo

    let method = match json_body.get("method") {
        Some(v) => v,
        None => {
            tracing::error!("Unable to get method from client request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot get method from body request JSON\"}}",
            ).into_response();
        }
    };

    let method = match method.as_str() {
        Some(v) => v,
        None => {
            tracing::error!("Unable to parse method from client request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "{\"error\":{\"code\":-32000,\"message\":\"Cannot parse method from body request JSON\"}}",
            ).into_response();
        }
    };

    let method_semi = extract_prefix(method);

    match method_semi {

        "engine_" => {
            match method {
                "engine_forkchoiceUpdatedV1" | "engine_forkchoiceUpdatedV2" => {
                    match handle_client_fcu(&body, &state).await {
                        Ok(v) => return (StatusCode::OK, v).into_response(),
                        Err(e) => {
                            tracing::error!("Unable to handle client request: {}", e);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                            ).into_response();
                        }
                    }
                },

                "engine_exchangeTransitionConfigurationV1" => {
                    match handle_client_exchangeconfig(&body, &state).await {
                        Ok(v) => return (StatusCode::OK, v).into_response(),
                        Err(e) => {
                            tracing::error!("Unable to handle client request: {}", e);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                            ).into_response();
                        }
                    }
                },
                
                "engine_newPayloadV1" | "engine_newPayloadV2" => {
                    match handle_client_newpayload(&body, &state).await {
                        Ok(v) => return (StatusCode::OK, v).into_response(),
                        Err(e) => {
                            tracing::error!("Unable to handle client request: {}", e);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                            ).into_response();
                        }
                    }
                },
                
                "engine_getPayloadV1" |
                "engine_getPayloadV2" |
                "engine_getPayloadBodiesByHashV1" |
                "engine_getPayloadBodiesByRangeV1" |
                "engine_exchangeCapabilities" => {
                    match handle_client_passto_auth(&body, &state).await {
                        Ok(v) => return (StatusCode::OK, v).into_response(),
                        Err(e) => {
                            tracing::error!("Unable to handle client request: {}", e);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                            ).into_response();
                        }
                    }
                },

                _ => {
                    tracing::error!("Unable to match engine method from client request");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "{\"error\":{\"code\":-32000,\"message\":\"Cannot match engine method from body request JSON\"}}",
                    ).into_response();
                }
            }
        },

        "web3_" | "eth_" | "net_" => {
            match handle_client_passto_unauth(&body, &state).await {
                Ok(v) => return (StatusCode::OK, v).into_response(),
                Err(e) => {
                    tracing::error!("Unable to handle client request: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("{{\"error\":{{\"code\":-32000,\"message\":\"{e}\"}}}}"),
                    ).into_response();
                }
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

async fn handle_canonical_cl() {
    todo!();
}



#[tokio::main]
async fn main() {
    let matches = clap::App::new("openexecution")
        .version("0.1.0")
        .author("TennisBowling <tennisbowling@tennisbowling.com>")
        .about("OpenExecution is a program that lets you control multiple CL's with one canonical CL")
        .setting(clap::AppSettings::ColoredHelp)
        .long_version("OpenExecution version 0.1.0 by TennisBowling <tennisbowling@tennisbowling.com>")
        .arg(
            clap::Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("Port to listen on")
                .takes_value(true)
                .default_value("7000"),
        )
        .arg(
            clap::Arg::with_name("jwt-secret")
                .short("j")
                .long("jwt-secret")
                .value_name("JWT")
                .help("Path to JWT secret file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("listen-addr")
                .short("addr")
                .long("listen-addr")
                .value_name("LISTEN")
                .help("Address to listen on")
                .takes_value(true)
                .default_value("0.0.0.0"),
        )
        .arg(
            clap::Arg::with_name("log-level")
                .short("l")
                .long("log-level")
                .value_name("LOG")
                .help("Log level")
                .takes_value(true)
                .default_value("info"),
        )
        .arg(
            clap::Arg::with_name("node")
                .short("n")
                .long("node")
                .value_name("NODE")
                .help("EL node to connect to for engine_ requests")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("unauth-node")
                .short("un")
                .long("unauth-node")
                .value_name("unauth_node")
                .help("unauth EL node to connect to (for non-engine_ requests)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("db-path")
                .short("d")
                .long("db-path")
                .value_name("DB")
                .help("Path to database")
                .takes_value(true)
                .default_value("./db"),
        )
    .get_matches();

    let port = matches.value_of("port").unwrap();
    let jwt_secret = matches.value_of("jwt-secret").unwrap();
    let listen_addr = matches.value_of("listen-addr").unwrap();
    let log_level = matches.value_of("log-level").unwrap();
    let node = matches.value_of("node").unwrap();
    let unauth_node = matches.value_of("unauth-node").unwrap();
    let db_path = matches.value_of("db-path").unwrap();


    let log_level = match log_level {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    // set log level with tracing subscriber
    let subscriber = tracing_subscriber::fmt().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
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

    let jwt_secret = &jsonwebtoken::EncodingKey::from_secret(&jwt_secret);

    tracing::trace!("Loaded JWT secret");



    //  setup db
    let db_path = std::path::Path::new(db_path);
    
    // if we don't have a db, create one
    if !db_path.exists() {
        std::fs::create_dir(db_path).expect("Unable to create db directory");
        tracing::info!("Created db at {:?}", db_path);
    }

    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host={} user=postgres password=postgres dbname=postgres",
            db_path.to_str().unwrap()
        ),
        tokio_postgres::NoTls
    ).await.expect("Unable to connect to postgres");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::error!("Connection error: {}", e);
        }
    });
    
    tracing::info!("Opened db at {:?}", db_path);

    // create tables if they don't exist

    client.query(
        "CREATE TABLE IF NOT EXISTS fcu (request TEXT NOT NULL UNIQUE, response TEXT NOT NULL UNIQUE);",
        &[],
    ).await.expect("Unable to create fcu table");

    client.query(
        "CREATE TABLE IF NOT EXISTS newpayload (request TEXT NOT NULL UNIQUE, response TEXT NOT NULL UNIQUE);",
        &[],
    ).await.expect("Unable to create newpayload table");

    client.query(
        "CREATE TABLE IF NOT EXISTS exchangeconfig (request TEXT NOT NULL UNIQUE, response TEXT NOT NULL UNIQUE);",
        &[],
    ).await.expect("Unable to create exchangeconfig table");
    

    let last_legitimate_fcu = String::new();

    
    // make the state
    let state = Arc::new(State{
        db: Arc::new(client),
        jwt_secret: Arc::new(jwt_secret.clone()),
        auth_node: Arc::new(Node{ client: reqwest::Client::new(), url: node.to_string() }),
        unauth_node: Arc::new(Node{ client: reqwest::Client::new(), url: unauth_node.to_string() }),
        last_legitimate_fcu: Arc::new(RwLock::new(last_legitimate_fcu)),
    });


    let app: Router = Router::new()
        .route("/", axum::routing::post(handle_client_cl))
        .route("/canonical", axum::routing::post(handle_canonical_cl))
        .layer(Extension(state.clone()))
        .layer(DefaultBodyLimit::disable())
    ;

    let addr = format!("{}:{}", listen_addr, port).parse();
    if let Err(e) = addr {
        tracing::error!("Unable to parse listen address: {}", e);
        std::process::exit(1);
    }
    let addr = addr.unwrap();

    tracing::info!("Listening on {}", addr);
    
    let server = axum::Server::bind(&addr)
        .serve(app.into_make_service());

    if let Err(e) = server.await {
        tracing::error!("Server error: {}", e);
    }



}
