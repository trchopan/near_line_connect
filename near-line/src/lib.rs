use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::env::block_timestamp_ms;
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault};

pub type LineId = String;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    // owner of contract;
    pub owner_id: AccountId,

    pub public_key: String,

    pub line_id_by_wallet: LookupMap<AccountId, LineId>,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId, public_key: String) -> Self {
        Self {
            owner_id: owner_id.clone().into(),
            public_key,
            line_id_by_wallet: LookupMap::new(owner_id.as_bytes()),
        }
    }

    pub fn get_line_id(&mut self, wallet: AccountId) -> Option<LineId >{
        self.line_id_by_wallet.get(&wallet)
    }

    #[payable]
    pub fn set_public_key(&mut self, public_key: String) {
        assert_eq!(env::predecessor_account_id(), self.owner_id, "Unauthorized");
        self.public_key = public_key;
    }

    #[payable]
    pub fn record_wallet_by_line_id(
        &mut self,
        signature: String,
        line_id: LineId,
        wallet: AccountId,
        expire: u64,
    ) -> String {
        use ed25519_dalek::Verifier;
        use ed25519_dalek::{PublicKey, Signature};

        let signature_bytes = hex::decode(signature).expect("Cannot decode signature");
        let signature_ =
            Signature::from_bytes(&signature_bytes).expect("Cannot create signature from bytes");
        let public_key_decode = hex::decode(&self.public_key).expect("Cannot decode public_key");
        let public_key =
            PublicKey::from_bytes(&public_key_decode).expect("Cannot create public_key bytes");

        let message = format!("{}{}{}", line_id, wallet, expire);
        let verify = public_key.verify(message.as_bytes(), &signature_);
        assert!(verify.is_ok(), "Verify failed");
        let current_timestamp = block_timestamp_ms();
        assert!(expire > current_timestamp, "Expired. block_timestamp_ms {}", current_timestamp);

        self.line_id_by_wallet.insert(&wallet, &line_id);

        "Success".to_string()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use near_sdk::AccountId;
    use near_sdk::MockedBlockchain;

    use super::*;

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::default();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_new() {
        let mut context = get_context(accounts(1));
        testing_env!(context.build());
        let owner_id: AccountId = "test.testnet".parse().unwrap();
        let contract = Contract::new(owner_id, "1234567".to_string());
        testing_env!(context.is_view(true).build());
        assert_eq!(contract.line_id_by_wallet.get(&"some".to_string()), None);
        assert_eq!(contract.public_key, "1234567");
    }
}
