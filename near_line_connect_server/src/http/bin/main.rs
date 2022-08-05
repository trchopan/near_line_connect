use actix_cors::Cors;
use actix_web::{
    delete, error, get,
    http::{header::ContentType, StatusCode},
    middleware::Logger,
    post,
    web::{Data, Json, Path},
    App, HttpResponse, HttpServer,
};
use clap::Parser;
use derive_more::{Display, Error};
use ed25519_dalek::Keypair;
use ed25519_dalek::Signer;
use ed25519_dalek::{PublicKey, SecretKey};
use env_logger::Env;
use near_line_connect_server::{read_key_file, KeyFile};
use reqwest::header::AUTHORIZATION;
use rusqlite::{self, Connection, Result};
use serde::{Deserialize, Serialize};
use std::{
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// API Server for Near Line Connect app
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

    /// SQLite database to save user information
    #[clap(long, value_parser)]
    db: std::path::PathBuf,

    /// the serving addr for the server. Example: 127.0.0.1:5000
    #[clap(long, value_parser)]
    addr: String,
}

struct MyData {
    keypair: Keypair,
    expire_sec: u64,
    conn: Mutex<rusqlite::Connection>,
}

type MyState = Data<MyData>;

#[derive(Serialize, Deserialize, Debug)]
struct LineProfileResp {
    sub: String,
    name: String,
    picture: String,
}

async fn verify_token(token: String) -> Result<LineProfileResp, reqwest::Error> {
    let url = "https://api.line.me/oauth2/v2.1/userinfo";
    let client = reqwest::Client::new();

    let resp = client
        .get(url)
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .send()
        .await;
    let res = resp?.json::<LineProfileResp>().await;
    res
}

#[derive(Serialize, Debug, Display, Error)]
#[serde(tag = "code")]
enum MyError {
    InternalError { msg: String },

    BadClientData { msg: String },

    NotFound,
}

impl error::ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .body(serde_json::to_string(self).unwrap())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            MyError::InternalError { msg: _ } => StatusCode::INTERNAL_SERVER_ERROR,
            MyError::BadClientData { msg: _ } => StatusCode::BAD_REQUEST,
            MyError::NotFound => StatusCode::NOT_FOUND,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SignLineOpt {
    line_id: String,
    token: String,
    wallet_id: String,
}

#[derive(Serialize, Deserialize)]
struct SignatureResp {
    signature: String,
    expire: u128,
}

#[post("/sign_registration")]
async fn sign_registration(
    my_data: MyState,
    line_opt: Json<SignLineOpt>,
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

        record_user_profile(&my_data.conn, &resp).expect("Cannot record_user_profile");
    }

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let expire_sec = u128::from(my_data.expire_sec);
    let expire = current_timestamp + expire_sec * 1000;
    let message = format!("{}{}{}", line_opt.line_id, line_opt.wallet_id, expire);
    let signature = my_data.keypair.sign(message.as_bytes());

    Ok(Json(SignatureResp {
        signature: signature.to_string(),
        expire,
    }))
}

#[derive(Serialize, Deserialize)]
struct DeleteLineOpt {
    token: String,
}

#[delete("/line_profile/{line_id}")]
async fn remove_line_profile(
    my_data: MyState,
    line_id: Path<String>,
    line_opt: Json<DeleteLineOpt>,
) -> Result<HttpResponse, MyError> {
    let verify_resp = verify_token(line_opt.token.clone()).await;
    if verify_resp.is_err() {
        return Err(MyError::BadClientData {
            msg: "cannot verify token".to_string(),
        });
    }

    if let Ok(resp) = verify_resp {
        if resp.sub != line_id.to_string() {
            return Err(MyError::BadClientData {
                msg: "cannot match token sub and provided line_id".to_string(),
            });
        }

        remove_user_profile(&my_data.conn, line_id.to_string())
            .expect("Cannot remove_user_profile");
    }
    Ok(HttpResponse::Ok().body(""))
}

#[get("/line_profile/{line_id}")]
async fn get_line_profile(
    my_data: MyState,
    line_id: Path<String>,
) -> Result<Json<LineProfileResp>, MyError> {
    let line_profile = get_user_profile(&my_data.conn, line_id.to_string());
    match line_profile {
        Ok(line_profile) => Ok(Json(line_profile)),
        Err(err) => match err {
            rusqlite::Error::QueryReturnedNoRows => Err(MyError::NotFound),
            err => Err(MyError::InternalError {
                msg: format!("cannot get {}: {}", line_id, err),
            }),
        },
    }
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

    let conn = Connection::open(args.db).expect("Cannot open db file");
    initialize_db(&conn).expect("Cannot initialize db");

    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let my_data = Data::new(MyData {
        keypair: Keypair {
            secret: secret_key,
            public: public_key,
        },
        expire_sec: args.expire_sec,
        conn: Mutex::new(conn),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Cors::permissive())
            .app_data(my_data.clone())
            .service(sign_registration)
            .service(remove_line_profile)
            .service(get_line_profile)
    })
    .bind(args.addr)?
    .run()
    .await
}

fn initialize_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "create table if not exists user_profiles (
             line_id text primary key,
             name text not null,
             picture text
         )",
        [],
    )?;

    Ok(())
}

fn record_user_profile(conn: &Mutex<Connection>, line_profile: &LineProfileResp) -> Result<()> {
    let conn = conn.lock().expect("Cannot get lock on db");
    conn.execute(
        "INSERT INTO user_profiles(line_id,name,picture)
            VALUES(?1, ?2, ?3)
            ON CONFLICT(line_id) DO UPDATE SET
                name=excluded.name,
                picture=excluded.picture;",
        [&line_profile.sub, &line_profile.name, &line_profile.picture],
    )?;
    Ok(())
}

fn remove_user_profile(conn: &Mutex<Connection>, line_id: String) -> Result<()> {
    let conn = conn.lock().expect("Cannot get lock on db");
    conn.execute("DELETE FROM user_profiles WHERE line_id=?1;", [line_id])?;
    Ok(())
}

fn get_user_profile(conn: &Mutex<Connection>, line_id: String) -> Result<LineProfileResp> {
    let conn = conn.lock().expect("Cannot get lock on db");

    conn.query_row(
        "SELECT line_id, name, picture FROM user_profiles WHERE line_id=?1",
        [line_id],
        |row| {
            Ok(LineProfileResp {
                sub: row.get(0).expect("failed line_id"),
                name: row.get(1).expect("failed name"),
                picture: row.get(2).expect("failed picture"),
            })
        },
    )
}
