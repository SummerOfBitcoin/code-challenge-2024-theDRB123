



// use hex;
// use secp256k1::ecdsa::Signature;
// use secp256k1::{PublicKey, Secp256k1};
// use secp256k1::Message;
// use sha2::{Digest, Sha256};
// use ripemd::{Digest as Digest160, Ripemd160};

// use crate::parsers::Input;
// use crate::segregators::segragator;




// // check if the input is valid or not, and then if vaid then add to verified_mempool

// //pending case
// pub fn _handle_taproot(input: &serde_json::Value) -> bool {
//     // println!("Taproot Transaction");
//     true
// }



// fn sha256(message: String) -> String {
//     let mut hasher = Sha256::new();
//     hasher.update(message);
//     let result = hasher.finalize();
//     hex::encode(result)
// }

// fn hash160(message: String) -> String {
//     let mut hasher = Ripemd160::new();

//     hasher.update(message);
//     let result = hasher.finalize();
//     hex::encode(result)
// }


// pub(crate) fn handle_p2pkh(input: &serde_json::Value) -> bool {
//     println!("P2PKH Transaction");

//     //unlocking script
//     let script_sig_asm = input["scriptsig_asm"].to_string();
//     let unlocking_pubkey = input["pubkey"].to_string();
//     let unlocking_signature_der = input["signature"].to_string();
//     let sighash_type = unlocking_signature_der[unlocking_signature_der.len()-2..unlocking_signature_der.len()].to_string();
//     let unlocking_signature_der = unlocking_signature_der[0..unlocking_signature_der.len()-2].to_string();

//     // inside this is the hexadecimal representation of the hash of the recipient public key without base58 encoding
//     let script_pubkey_asm = input["prevout"]["scriptpubkey_asm"].to_string();
//     let locking_pubkey_hash = script_pubkey_asm.split_ascii_whitespace().nth(3).unwrap();

//     //sha256 -> ripemd160
//     let sha256_hash = sha256(unlocking_pubkey.clone());
//     let ripemd160_hash = hash160(sha256_hash);

//     //check if the unlocking pubkey hash is equal to the locking pubkey hash
//     if ripemd160_hash != locking_pubkey_hash {
//         return false;
//     }
//     //proceed further to check signatures
//     let signature_bytes = hex::decode(unlocking_signature_der).expect("Invalid signature format");
//     let pubkey_bytes = hex::decode(unlocking_pubkey).expect("Invalid public key format");



//     let secp = Secp256k1::new();
//     let signature = Signature::from_der(&signature_bytes).expect("Invalid signature format");
//     let pubkey = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");


//     // Compute the sighash
//     // This is a placeholder. You need to replace this with the actual transaction data.
//     let tx_data = "placeholder";
//     // let sighash = compute_sighash(tx_data);

//     // Verify the signature
//     // let message = Message::from_slice(&sighash).expect("Invalid sighash");
//     // secp.verify(&message, &signature, &pubkey).is_ok()
    
    
    
//     true
// }

// pub(crate) fn test_handler(input: Input) -> bool {
//     println!("Test Transaction");
//     true
// }

// pub(crate) fn handle_p2sh(input: &serde_json::Value) -> bool {
//     println!("P2SH Transaction");
//     true
// }

// pub(crate) fn handle_p2wpkh(input: &serde_json::Value) -> bool {
//     println!("P2WPKH Transaction");
//     true
// }

// pub(crate) fn handle_p2wsh(input: &serde_json::Value) -> bool {
//     println!("P2WSH Transaction");

//     // stack looks like -> <sig> <pubkey> <opdup> <ophash160> <pubkeyhash> <opequalverify> <opchecksig>

//     true
// }

// pub(crate) fn handle_p2sh_p2wpkh(input: &serde_json::Value) -> bool {
//     println!("P2SH-P2WPKH Transaction");
//     true
// }

// pub(crate) fn handle_p2sh_p2wsh(input: &serde_json::Value) -> bool {
//     println!("P2SH-P2WSH Transaction");
//     true
// }
