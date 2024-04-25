extern crate hex;
extern crate serde_json;


use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Read, vec};

pub(crate) fn encode_varint(num: u64) -> Vec<u8> {
    if num < 0xfd {
        return vec![num as u8];
    } else if num <= 0xffff {
        return [vec![0xfd], (num as u16).to_le_bytes().to_vec()].concat();
    } else if num <= 0xffffffff {
        return [vec![0xfe], (num as u32).to_le_bytes().to_vec()].concat();
    } else {
        return [vec![0xff], (num as u64).to_le_bytes().to_vec()].concat();
    }
}

fn encode_varstr(s: Vec<u8>) -> Vec<u8> {
    let mut varstr = encode_varint(s.len() as u64);
    varstr.extend(s);
    varstr
}

pub fn serialize_input(tx_input: &Value) -> Vec<u8> {
    let mut out = vec![];
    let txid_bytes: Vec<u8> =
        hex::decode(tx_input["txid"].as_str().unwrap()).expect("Invalid hex in txid");
    out.extend(txid_bytes.iter().rev());
    out.extend(&(tx_input["vout"].as_u64().unwrap() as u32).to_le_bytes());
    let binding = json!("");
    let script_sig_hex = tx_input
        .get("scriptsig")
        .unwrap_or(&binding)
        .as_str()
        .unwrap();
    let script_sig_bytes: Vec<u8> = hex::decode(script_sig_hex).expect("Invalid hex in scriptsig");
    let script_sig_encoded = encode_varstr(script_sig_bytes);
    out.extend(script_sig_encoded);
    out.extend(&(tx_input["sequence"].as_u64().unwrap() as u32).to_le_bytes());
    out
}

pub fn serialize_output(tx_output: &Value) -> Vec<u8> {
    let mut out = vec![];
    out.extend(&(tx_output["value"].as_u64().unwrap()).to_le_bytes());
    let script_pubkey_hex = tx_output["scriptpubkey"].as_str().unwrap();
    let script_pubkey_bytes: Vec<u8> =
        hex::decode(script_pubkey_hex).expect("Invalid hex in scriptpubkey");
    let script_pubkey_encoded = encode_varstr(script_pubkey_bytes);
    out.extend(script_pubkey_encoded);
    out
}

pub fn serialize_witness(witness: &Value) -> Vec<u8> {
    let mut out = vec![];
    let witness_len = witness.as_array().unwrap().len() as u64;
    out.extend(encode_varint(witness_len));
    for item in witness.as_array().unwrap() {
        let item_bytes: Vec<u8> =
            hex::decode(item.as_str().unwrap()).expect("Invalid hex in witness item");
        let item_encoded = encode_varstr(item_bytes);
        out.extend(item_encoded);
    }
    out
}

pub fn serialize_tx(tx: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut out = vec![];
    let mut alt_out = vec![];
    let mut wit_out = vec![];


    out.extend(&(tx["version"].as_u64().unwrap() as u32).to_le_bytes());
    alt_out.extend(&out);

    let mut segwit = false;
    for vin in tx["vin"].as_array().unwrap() {
        if vin["witness"].is_array() {
            out.extend(&[0x00, 0x01]); // witness flag
            wit_out.extend(&[0x00, 0x01]);
            segwit = true;
            break;
        }
    }
    out.extend(encode_varint(tx["vin"].as_array().unwrap().len() as u64));
    alt_out.extend(encode_varint(tx["vin"].as_array().unwrap().len() as u64));

    for tx_input in tx["vin"].as_array().unwrap() {
        out.extend(serialize_input(&tx_input));
        alt_out.extend(serialize_input(&tx_input));
    }
    out.extend(encode_varint(tx["vout"].as_array().unwrap().len() as u64));
    alt_out.extend(encode_varint(tx["vout"].as_array().unwrap().len() as u64));
    for tx_output in tx["vout"].as_array().unwrap() {
        out.extend(serialize_output(&tx_output));
        alt_out.extend(serialize_output(&tx_output));
    }
    if segwit {
        for tx_input in tx["vin"].as_array().unwrap() {
            if tx_input["witness"].is_array() {
                out.extend(serialize_witness(&tx_input["witness"]));
                wit_out.extend(serialize_witness(&tx_input["witness"]));
            }
        }
    }
    out.extend(&(tx["locktime"].as_u64().unwrap() as u32).to_le_bytes());
    alt_out.extend(&(tx["locktime"].as_u64().unwrap() as u32).to_le_bytes());

    //out -> complete serialization, alt_out -> removed witness data, wit_out -> witness data, alt_out + wit_out != out 
    //out -> for wtxids
    (out, alt_out, wit_out)
}

pub fn serializer(tx:&Value) -> (String, String, String) {
    let serialized_tx = serialize_tx(&tx);
    let hex_serialized_tx = (hex::encode(&serialized_tx.0), hex::encode(&serialized_tx.1), hex::encode(&serialized_tx.2));
    return hex_serialized_tx;
}

pub fn txid_maker(transaction_hex: String) -> String {
    let bytes = hex::decode(transaction_hex).expect("Invalid hexadecimal string");

    let mut hasher = Sha256::new();

    hasher.update(&bytes);
    let first_hash = hasher.finalize_reset();

    hasher.update(&first_hash);
    let second_hash = hasher.finalize_reset();

    return hex::encode(second_hash);
}

pub(crate) fn generate_sighash_legacy(tx: Value, index: usize, sighash_flag: u8) -> Vec<u8> {
    //go through each input, and remove the scriptsig
    //then replace sigscript with the scriptpubkey of the output at the index
    let mut sighash_txn = tx.clone();
    for input in sighash_txn["vin"].as_array_mut().unwrap() {
        input["scriptsig"] = "".into();
    }

    let script_pubkey = tx["vin"][index as usize]["prevout"]["scriptpubkey"]
        .as_str()
        .unwrap();
    sighash_txn["vin"][index as usize]["scriptsig"] = script_pubkey.into();

    let mut serialized_txn_in_bytes = serialize_tx(&sighash_txn).1;

    let sighash_flag_bytes = [sighash_flag, 0, 0, 0];
    serialized_txn_in_bytes.extend_from_slice(&sighash_flag_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&serialized_txn_in_bytes);
    let mut result = hasher.finalize_reset();
    hasher.update(&result);
    result = hasher.finalize_reset();
    result.to_vec()
}

pub(crate) struct Reusables {
    version: [u8; 4],
    input_txn_vout_hash: Vec<u8>,
    sequence_hash: Vec<u8>,
    output_hash: Vec<u8>,
    locktime: [u8; 4],
}

pub(crate) fn generate_preimage_segwit(
    tx: Value,
    index: usize,
    sighash_flag: u8,
    reusables: &Reusables,
) -> Vec<u8> {
    //serialize the TXID+VOUT for the current input
    let mut input: Vec<u8> = vec![];
    let txid_bytes =
        hex::decode(tx["vin"][index]["txid"].as_str().unwrap()).expect("Invalid hex in txid");
    let vout = (tx["vin"][index]["vout"].as_u64().unwrap() as u32).to_le_bytes();

    input.extend(txid_bytes.iter().rev());
    input.extend(vout);

    //create the scriptcode for the required input
    let scriptpubkey_asm = tx["vin"][index]["prevout"]["scriptpubkey_asm"]
        .as_str()
        .unwrap();
    let publickey_hash = scriptpubkey_asm.split_ascii_whitespace().nth(2).unwrap();
    // let scriptcode = String::from("1976a914").add(publickey_hash);
    //below is for p2wpkh
    let scriptcode = hex::decode(format!("{}{}{}", "1976a914", publickey_hash, "88ac")).unwrap();

    //for p2wsh
    //TODO

    let amount = (tx["vin"][index]["prevout"]["value"].as_u64().unwrap()).to_le_bytes();
    let sequence = (tx["vin"][index]["sequence"].as_u64().unwrap() as u32).to_le_bytes();
    let sighash_flag = [sighash_flag, 0, 0, 0];

    let mut preimage_bytes: Vec<u8> = vec![];

    preimage_bytes.extend(reusables.version.iter());
    preimage_bytes.extend(reusables.input_txn_vout_hash.iter());
    preimage_bytes.extend(reusables.sequence_hash.iter());
    preimage_bytes.extend(input.iter());
    preimage_bytes.extend(scriptcode);
    preimage_bytes.extend(amount.iter());
    preimage_bytes.extend(sequence.iter());
    preimage_bytes.extend(reusables.output_hash.iter());
    preimage_bytes.extend(reusables.locktime.iter());
    preimage_bytes.extend(sighash_flag.iter());

    // println!("Preimage = {}", hex::encode(&preimage_bytes));

    let mut hasher = Sha256::new();
    hasher.update(&preimage_bytes);
    let result = hasher.finalize_reset();
    hasher.update(&result);
    let result = hasher.finalize_reset();
    result.to_vec()
}

pub(crate) fn create_reusables(tx: &Value) -> Reusables {
    let version_ln_bytes = (tx["version"].as_u64().unwrap() as u32).to_le_bytes();

    let mut input_txn_vout_hash: Vec<u8> = vec![];

    for (index, input) in tx["vin"].as_array().unwrap().iter().enumerate() {
        let txid = hex::decode(input["txid"].as_str().unwrap()).expect("Invalid hex in txid");
        input_txn_vout_hash.extend(txid.iter().rev());

        let vout = (input["vout"].as_u64().unwrap() as u32).to_le_bytes();
        input_txn_vout_hash.extend(vout);
    }

    let mut hasher = Sha256::new();
    hasher.update(&input_txn_vout_hash);
    let input_txn_vout_hash = hasher.finalize_reset();
    hasher.update(&input_txn_vout_hash);
    let input_txn_vout_hash = hasher.finalize_reset().to_vec();

    //now create for sequences
    let mut sequence_serialized: Vec<u8> = vec![];

    for (index, input) in tx["vin"].as_array().unwrap().iter().enumerate() {
        let sequence_bytes = (input["sequence"].as_u64().unwrap() as u32).to_le_bytes();
        sequence_serialized.extend(sequence_bytes);
    }

    hasher.update(sequence_serialized);
    let sequence_hash = hasher.finalize_reset().to_vec();
    hasher.update(sequence_hash);
    let sequence_hash = hasher.finalize_reset().to_vec();

    //serialize and hash all the outputs
    let mut txn_outputs_serialized: Vec<u8> = vec![];
    for output in tx["vout"].as_array().unwrap() {
        txn_outputs_serialized.extend(serialize_output(output));
        // let script_pub_key = output["scriptpubkey"]
    }

    // println!("Serialized output-> {}", hex::encode(&txn_outputs_serialized));
    hasher.update(&txn_outputs_serialized);
    let output_hash = hasher.finalize_reset().to_vec();
    hasher.update(output_hash);
    let output_hash = hasher.finalize_reset().to_vec();

    //get the locktime from the transaction
    let locktime = (tx["locktime"].as_u64().unwrap() as u32).to_le_bytes();
    //convert to string

    Reusables {
        version: version_ln_bytes,
        input_txn_vout_hash: input_txn_vout_hash,
        sequence_hash: sequence_hash,
        output_hash: output_hash,
        locktime: locktime,
    }
}
