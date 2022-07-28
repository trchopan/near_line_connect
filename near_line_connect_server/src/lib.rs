use std::fs;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum KeyScheme {
    Ed25519Public,
    Ed25519Secret,
    Unknown(String),
}

#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    pub name: KeyScheme,
    pub hex: String,
}

pub fn read_key_file(fp: std::path::PathBuf) -> KeyFile {
    let contents = fs::read_to_string(fp).expect("Something went wrong reading the file");
    serde_json::from_str::<KeyFile>(&contents).expect("Cannot parse key file")
}
