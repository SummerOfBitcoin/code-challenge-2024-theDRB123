use secp256k1::{
    ecdsa::Signature,
    Message, PublicKey, Secp256k1,
};
use crate::serialization;


pub fn validate_legacy(txn: &str) -> bool {
    let txn: serde_json::Value = serde_json::from_str(txn).unwrap();

    let mut is_valid = true;

    //iterate through each input, use the sighash function and then validate the signature
    for (index, input) in txn["vin"].as_array().unwrap().iter().enumerate() {
        let txn_temp = txn.clone();

        //now verify the sighash with the signature
        let scriptsig_asm = txn["vin"][index]["scriptsig_asm"].as_str().unwrap();
        let publickey =
            hex::decode(scriptsig_asm.split_ascii_whitespace().nth(3).unwrap()).unwrap();

        let signature =
            hex::decode(scriptsig_asm.split_ascii_whitespace().nth(1).unwrap()).unwrap();
        let sighash_flag = *signature.last().unwrap();

        let sighash = serialization::generate_sighash_legacy(txn_temp, index, sighash_flag);

        let signature = signature[..signature.len() - 1].to_vec();
        is_valid = verify_signature(sighash, publickey, signature);
    }
    is_valid
}

pub fn validate_segwit(txn: &serde_json::Value) -> bool {
    let mut is_valid = true;
    let reusables = serialization::create_reusables(&txn.clone());

    for (index, input) in txn["vin"].as_array().unwrap().iter().enumerate() {
        let txn_temp = txn.clone();
        //if segwit
        if input["prevout"]["scriptpubkey_type"] == "v0_p2wpkh" {
            let public_key =
                hex::decode(txn["vin"][index]["witness"][1].as_str().unwrap()).unwrap();
            let signature = hex::decode(txn["vin"][index]["witness"][0].as_str().unwrap()).unwrap();
            let sighash_flag = *signature.last().unwrap();
            let preimage_hash =
                serialization::generate_preimage_segwit(txn_temp, index, sighash_flag, &reusables);
            let signature = signature[..signature.len() - 1].to_vec();

            is_valid = verify_signature(preimage_hash, public_key, signature);
        } else {
            let scriptsig_asm = txn["vin"][index]["scriptsig_asm"]
                .as_str()
                .unwrap();
            let public_key =
                hex::decode(scriptsig_asm.split_ascii_whitespace().nth(3).unwrap()).unwrap();
            let signature =
                hex::decode(scriptsig_asm.split_ascii_whitespace().nth(1).unwrap()).unwrap();
            let sighash_flag = *signature.last().unwrap();
            let sighash = serialization::generate_sighash_legacy(txn_temp, index, sighash_flag);

            let signature = signature[..signature.len() - 1].to_vec();

            is_valid = verify_signature(sighash, public_key, signature);
        }
    }

    return is_valid;
}

pub fn verify_signature(msg_hash: Vec<u8>, pub_key: Vec<u8>, sig: Vec<u8>) -> bool {
    let secp = Secp256k1::verification_only();
    let message = Message::from_digest_slice(&msg_hash).unwrap();
    let pubkey = PublicKey::from_slice(&pub_key).unwrap();
    let signature = Signature::from_der(&sig).unwrap();

    // secp.verify_ecdsa(msg, sig, pk)
    secp.verify_ecdsa(&message, &signature, &pubkey).is_ok()
}
