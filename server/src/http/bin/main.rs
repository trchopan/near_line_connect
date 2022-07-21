use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

fn main() {
    // Initialization of VRF context by providing a curve
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key =
        hex::decode("866b26669046d821f558ad2be5a80ac14bd7ecaf2cfd5177c97a8722e43d5e19ab585422cc2aa0d5194a06941d292793c3cf044dc8f45657ecac1945512e2c9d").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    println!("public>> {:?}", hex::encode(&public_key));

    let message: &[u8] = b"sample";

    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();
    // pi[2] = 12u8;

    let hash = vrf.proof_to_hash(&pi).unwrap();

    println!("hash>> {:?}", hex::encode(hash));

    // VRF proof verification (returns VRF hash output)
    let beta = match vrf.verify(&public_key, &pi, &message) {
        Ok(hash) => hex::encode(hash),
        Err(err) => format!("not match {:?}", err),
    };
    println!("beta>> {:?}", beta);
}
