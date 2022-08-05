use std::fs;

use clap::Parser;

use ed25519_dalek::Keypair;
use ed25519_dalek::Verifier;
use ed25519_dalek::{PublicKey, SecretKey};
use ed25519_dalek::{Signature, Signer};
use near_line_connect_server::{read_key_file, read_key_file, Key};
use rand::rngs::OsRng;

/// Handle deriving VRF public key
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    /// Generate secret and public key pair into files
    GenKey {
        /// The secret key file path
        #[clap(long, parse(from_os_str))]
        secret_key: std::path::PathBuf,

        /// The public key file path
        #[clap(long, value_parser)]
        public_key: std::path::PathBuf,
    },

    /// Sign the message with both Public and Secret key
    Sign {
        /// The secret key file path
        #[clap(long, parse(from_os_str))]
        secret_key: std::path::PathBuf,

        /// The public key file path
        #[clap(long, value_parser)]
        public_key: std::path::PathBuf,

        /// The message to verify
        #[clap(long, value_parser)]
        message: String,
    },

    /// Verify the message with public key
    Verify {
        /// The public key string
        #[clap(long, value_parser)]
        public_key: String,

        /// The signature produced by `sign` command
        #[clap(long, value_parser)]
        signature: String,

        /// The message to verify
        #[clap(long, value_parser)]
        message: String,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::GenKey {
            public_key,
            secret_key,
        } => {
            let mut csprng = OsRng {};
            let keypair: Keypair = Keypair::generate(&mut csprng);
            let secret_key_file = KeyFile {
                name: KeyScheme::Ed25519Secret,
                hex: hex::encode(&keypair.secret),
            };
            let secret_key_string =
                serde_json::to_string(&secret_key_file).expect("secret keyfile failed");
            fs::write(secret_key, secret_key_string).expect("write secret keyfile failed");

            let public_key_file = KeyFile {
                name: KeyScheme::Ed25519Secret,
                hex: hex::encode(&keypair.public),
            };
            let public_key_string =
                serde_json::to_string(&public_key_file).expect("public keyfile failed");

            fs::write(public_key, public_key_string).expect("write public keyfile failed");

            println!("keypair saved!");
        }
        Commands::Sign {
            secret_key,
            public_key,
            message,
        } => {
            let secret_key_file: KeyFile = read_key_file(secret_key);
            let secret_key_string =
                hex::decode(secret_key_file.hex).expect("Cannot decode secret_key");
            let secret_key =
                SecretKey::from_bytes(&secret_key_string).expect("Cannot decode secret_key bytes");

            let public_key_file: KeyFile = read_key_file(public_key);
            let public_key_string =
                hex::decode(public_key_file.hex).expect("Cannot decode public_key");
            let public_key =
                PublicKey::from_bytes(&public_key_string).expect("Cannot decode public_key bytes");

            let key_pair = Keypair {
                secret: secret_key,
                public: public_key,
            };

            let signature = key_pair.sign(message.as_bytes());
            println!("proof>> {:?}", hex::encode(signature.to_bytes()));
        }
        Commands::Verify {
            public_key,
            signature,
            message,
        } => {
            let signature_bytes = hex::decode(signature).expect("Cannot decode signature");
            let signature_ = Signature::from_bytes(&signature_bytes)
                .expect("Cannot create signature from bytes");
            let public_key_decode = hex::decode(public_key).expect("Cannot decode public_key");
            let public_key =
                PublicKey::from_bytes(&public_key_decode).expect("Cannot create public_key bytes");

            match public_key.verify(message.as_bytes(), &signature_) {
                Ok(_) => println!("proof is truthful"),
                Err(err) => println!("bad signature {:?}", err),
            }
        }
    }
}
