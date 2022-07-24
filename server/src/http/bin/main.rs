use derive_more::{Display, Error};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;

use env_logger::Env;

use actix_web::{
    error,
    http::{header::ContentType, StatusCode},
    middleware::Logger,
    post,
    web::{Data, Json},
    App, HttpResponse, HttpServer,
};
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

use ed25519_dalek::Keypair;
use ed25519_dalek::Signer;
use ed25519_dalek::{PublicKey, SecretKey};
use near_line_connect::{read_key_file, KeyFile};

/// Handle deriving VRF public key
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The secret key file path
    #[clap(long, parse(from_os_str))]
    secret_key: std::path::PathBuf,

    /// The public key file path
    #[clap(long, value_parser)]
    public_key: std::path::PathBuf,

    /// The length of expire time in seconds
    #[clap(long, value_parser)]
    expire_sec: u64,
}

#[derive(Serialize, Deserialize)]
struct LineOpt {
    line_id: String,
    token: String,
    wallet_id: String,
}

#[derive(Serialize, Deserialize)]
struct SignatureResp {
    signature: String,
    expire: u128,
}

#[derive(Serialize, Deserialize, Debug)]
struct LineVerifyResp {
    sub: String,
    name: String,
    picture: String,
}

async fn verify_token(token: String) -> Result<LineVerifyResp, reqwest::Error> {
    let url = "https://api.line.me/oauth2/v2.1/userinfo";
    let client = reqwest::Client::new();

    let resp = client
        .get(url)
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .send()
        .await;
    let res = resp?.json::<LineVerifyResp>().await;
    res
}

#[derive(Serialize, Debug, Display, Error)]
#[serde(tag = "code")]
enum MyError {
    InternalError,

    BadClientData { msg: String },

    Timeout,
}

impl error::ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .body(serde_json::to_string(self).unwrap())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            MyError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            MyError::BadClientData { msg: _ } => StatusCode::BAD_REQUEST,
            MyError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

#[post("/sign_registration")]
async fn sign_registration(
    key_pair: Data<Keypair>,
    expire_sec: Data<u64>,
    line_opt: Json<LineOpt>,
) -> Result<Json<SignatureResp>, MyError> {
    let verify_resp = verify_token(line_opt.token.clone()).await;
    if verify_resp.is_err() {
        return Err(MyError::BadClientData {
            msg: "cannot verify token".to_string(),
        });
    }

    if let Ok(resp) = verify_resp {
        if resp.sub != line_opt.line_id {
            return Err(MyError::BadClientData {
                msg: "cannot match token sub and provided line_id".to_string(),
            });
        }
    }

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let expire_sec = u128::from(*expire_sec.as_ref());
    let expire = current_timestamp + expire_sec * 1000;
    let message = format!("{}{}{}", line_opt.line_id, line_opt.wallet_id, expire);
    let signature = key_pair.sign(message.as_bytes());

    Ok(Json(SignatureResp {
        signature: signature.to_string(),
        expire,
    }))
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let secret_key_file: KeyFile = read_key_file(args.secret_key);
    let secret_key_string = hex::decode(secret_key_file.hex).expect("Cannot decode secret_key");
    let secret_key =
        SecretKey::from_bytes(&secret_key_string).expect("Cannot decode secret_key bytes");

    let public_key_file: KeyFile = read_key_file(args.public_key);
    let public_key_string = hex::decode(public_key_file.hex).expect("Cannot decode public_key");
    let public_key =
        PublicKey::from_bytes(&public_key_string).expect("Cannot decode public_key bytes");

    let key_pair = Data::new(Keypair {
        secret: secret_key,
        public: public_key,
    });

    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(Data::clone(&key_pair))
            .app_data(Data::new(args.expire_sec))
            .service(sign_registration)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
