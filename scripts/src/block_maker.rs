use std::{
    fs,
    io::{Read, Write},
    time::{SystemTime, UNIX_EPOCH},
    vec,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{serialization, validation};

pub(crate) fn block_maker() {
    use std::time::Instant;

    let now = Instant::now();

    let transactions_json = read_trasactions();
    println!("transactions read");
    println!("Elapsed: {:?}", now.elapsed());

    let now = Instant::now();

    //select the valid transactions
    let mut transactions = transaction_selector(transactions_json);
    println!("transactions selected");
    println!("Elapsed: {:?}", now.elapsed());

    //before creating the wtxid, we add 000... as the coinbase transaction to it,
    // transactions.1.insert(0, "0000000000000000000000000000000000000000000000000000000000000000".to_string());

    let (mut txids, mut wtxids) = create_txid_wtxid(&transactions.0, &transactions.1);
    wtxids.insert(
        0,
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );

    let merkle_wtxid = create_merkle_root(&wtxids);

    let coinbase_txn = create_coin_base(&merkle_wtxid, &transactions.2);

    transactions.0.insert(0, coinbase_txn.clone().0);

    txids.insert(0, serialization::txid_maker(coinbase_txn.clone().0));

    let merkle_txid = create_merkle_root(&txids);
    let block_header = create_block_header(merkle_txid);

    // add the block header, serialized coinbase txn & list of all included txn in the output.txt file
    let mut file = fs::File::create("../output.txt").expect("Unable to create file");
    file.write_all(block_header.as_bytes())
        .expect("Unable to write to file");
    file.write_all("\n".as_bytes())
        .expect("Unable to write to file");
    file.write_all(coinbase_txn.0.as_bytes())
        .expect("Unable to write to file");
    file.write_all("\n".as_bytes())
        .expect("Unable to write to file");
    for txn in txids {
        let mut bytes = hex::decode(txn).unwrap();
        bytes.reverse();
        file.write_all(hex::encode(bytes).as_bytes())
            .expect("Unable to write to file");
        file.write_all("\n".as_bytes())
            .expect("Unable to write to file");
    }
    file.write_all("\n".as_bytes())
        .expect("Unable to write to file");
}

fn create_block_header(merkle_root: String) -> String {
    let version = "04000000";
    let prevous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"; //32 bytes of zeroes
    let time = get_time();
    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let bits = "ffff001f";

    // let nonce = "42a14695"; //random number
    let header = format!(
        "{}{}{}{}{}",
        version, prevous_block_hash, merkle_root, time, bits
    );
    let header = mine_header(&target, header);
    header
}

fn get_time() -> String {
    let now = SystemTime::now();
    let current = now
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as u32;

    hex::encode(current.to_le_bytes())
}

pub(crate) fn hash256(data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize_reset();
    hasher.update(result);

    let data = hasher.finalize_reset();
    data.to_vec()
}

fn mine_header(target: &str, header: String) -> String {
    let mut nonce: u32 = 0;
    let target_bytes = hex::decode(target).expect("Target invalid");
    let header_bytes_ = hex::decode(header).expect("Counldnt decode hex");

    loop {
        let mut header_bytes = header_bytes_.clone();
        header_bytes.extend(nonce.to_le_bytes());

        let mut hash_bytes = hash256(&header_bytes);
        hash_bytes.reverse();
        //compare hash with the target
        if hash_bytes < target_bytes {
            println!("Found a block");
            println!("Nonce = {}", nonce);
            return hex::encode(&header_bytes);
        }
        nonce += 1;
    }
}

fn create_txid_wtxid(txns: &Vec<String>, wtxns: &Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut txids: Vec<String> = vec![];
    let mut wtxids: Vec<String> = vec![];
    let mut hasher = Sha256::new();
    for txn in txns {
        let txn_bytes = hex::decode(&txn).expect("Couldnt parse hex");

        hasher.update(txn_bytes);
        let result = hasher.finalize_reset();
        hasher.update(result);
        let result = hasher.finalize_reset();
        let txid = hex::encode(result);

        txids.push(txid);
    }

    for wtxn in wtxns {
        let txn_seg_bytes = hex::decode(wtxn).expect("Couldnt parse hex");
        hasher.update(txn_seg_bytes);
        let result = hasher.finalize_reset();
        hasher.update(result);
        let result = hasher.finalize_reset();
        let wtxid = hex::encode(result);
        wtxids.push(wtxid);
    }

    return (txids, wtxids);
}

fn transaction_selector(txns: Vec<String>) -> (Vec<String>, Vec<String>, usize) {
    let mut txvec: Vec<String> = vec![];
    let mut wtxvec: Vec<String> = vec![];
    let mut weight: usize = 0;
    let mut bytes: usize = 0;
    let mut total_fees: usize = 0;

    for transaction in txns {
        let tx: Value = serde_json::from_str(&transaction).expect("Error parsing JSON");

        if !check_p2wpkh(&tx) {
            continue;
        }
        if !validation::validate_segwit(&tx) {
            continue;
        }
        let serialized_tx = serialization::serializer(&tx);
        let fees = calculate_fees(tx);
        let txwt = calculate_weight(&serialized_tx.1, &serialized_tx.2);
        if weight + txwt < 4000000 - 1000 {
            wtxvec.push(serialized_tx.clone().0); //for wtxid
            txvec.push(serialized_tx.clone().1); //for txid
            weight += txwt;
            bytes += serialized_tx.1.len() / 2 + serialized_tx.2.len() / 8;
            total_fees += fees;
        }
    }
    println!("Total fees generated = {}", total_fees);
    println!("Transaction selected");
    return (txvec, wtxvec, total_fees);
}

pub fn check_p2wpkh(txn: &serde_json::Value) -> bool {
    for input in txn["vin"].as_array().unwrap() {
        if input["prevout"]["scriptpubkey_type"].as_str().unwrap() != "v0_p2wpkh"
        {
            return false;
        } else {
            continue;
        }
    }
    true
}

pub fn check_p2wpkh_pkh(txn: &serde_json::Value) -> bool {
    for input in txn["vin"].as_array().unwrap() {
        if input["prevout"]["scriptpubkey_type"].as_str().unwrap() != "v0_p2wpkh"
        && input["prevout"]["scriptpubkey_type"].as_str().unwrap() != "p2pkh"
        {
            return false;
        } else {
            continue;
        }
    }
    true
}

pub fn _check_p2pkh(txn: &serde_json::Value) -> bool {
    for input in txn["vin"].as_array().unwrap() {
        if input["prevout"]["scriptpubkey_type"].as_str().unwrap() != "p2pkh" {
            return false;
        } else {
            continue;
        }
    }
    true
}

fn calculate_fees(tx: serde_json::Value) -> usize {
    let mut inputs: usize = 0;
    let mut outputs: usize = 0;
    let mut fees: usize = 0;
    for input in tx["vin"].as_array().unwrap() {
        inputs = inputs + input["prevout"]["value"].as_u64().unwrap() as usize;
    }
    for output in tx["vout"].as_array().unwrap() {
        outputs = outputs + output["value"].as_u64().unwrap() as usize;
    }
    fees = inputs - outputs;
    return fees;
}

fn calculate_weight(txn_data: &String, wit_data: &String) -> usize {
    let txn_weight = txn_data.len() / 2 * 4;
    let wit_weight = wit_data.len() / 2;

    txn_weight + wit_weight
}

fn create_coin_base(merkle_root: &String, txn_fees: &usize) -> (String, String) {
    let new_satoshis = txn_fees.clone();
    let mut coinbase = return_coinbase();
    coinbase["vout"][0]["value"] = serde_json::Value::from(new_satoshis);

    let witness_commitment = calculate_witness_commitment(merkle_root);

    coinbase["vout"][1]["scriptpubkey"] =
        serde_json::Value::from(format!("{}{}", "6a24aa21a9ed", witness_commitment));
    coinbase["vout"][1]["scriptpubket_asm"] = serde_json::Value::from(format!(
        "{}{}",
        "OP_0 OP_PUSHBYTES_36 aa21a9ed", witness_commitment
    ));
    
    let coinbase_bytes = serialization::serialize_tx(&coinbase);
    let coinbase_hex = hex::encode(coinbase_bytes.0); //complete coinbase
    let coinbase_wit_hex = hex::encode(coinbase_bytes.1); //without witness data
    return (coinbase_hex, coinbase_wit_hex);
}

fn calculate_witness_commitment(witness_root: &String) -> String {
    let witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000";
    let wrv_bytes = hex::decode(witness_reserved_value).unwrap();
    let wr_bytes = hex::decode(witness_root).unwrap();
    let mut wc: Vec<u8> = vec![];
    wc.extend(wr_bytes);
    wc.extend(wrv_bytes);

    let hash = hash256(&wc);
    hex::encode(hash)
}

fn create_merkle_root(transactions: &Vec<String>) -> String {
    if transactions.len() == 1 {
        return transactions.first().unwrap().clone();
    }

    let mut results: Vec<String> = vec![];

    //take transactions from the array, and then add to results
    for i in (0..transactions.len()).step_by(2) {
        let txn1 = &transactions[i];
        let txn2: &String;
        //if another transaction there
        if i < transactions.len() - 1 {
            txn2 = &transactions[i + 1];
        } else {
            txn2 = txn1;
        }

        let mut txn = hex::decode(txn1).unwrap();
        txn.extend(hex::decode(txn2).unwrap());

        //now create the hash of these
        let mut hasher = Sha256::new();
        hasher.update(txn);
        let hashed = hasher.finalize_reset();
        hasher.update(hashed);
        let hashed = hasher.finalize_reset();
        results.push(hex::encode(hashed));
    }

    create_merkle_root(&results)
}

fn read_trasactions() -> Vec<String> {
    let path = "../mempool";
    let directory = fs::read_dir(path).unwrap();

    let mut transactions: Vec<String> = vec![];

    for transaction in directory {
        let transaction = transaction.expect("Unable to read directory transaction");
        if transaction.path().is_file() {
            let path = transaction.path();
            let mut file = fs::File::open(path).expect("File not found");
            let mut tx_data = String::new();
            file.read_to_string(&mut tx_data)
                .expect("Error reading file");
            transactions.push(tx_data);
        }
    }

    return transactions;
}

fn return_coinbase() -> serde_json::Value {
    let txn = r#"
    {
    "version": 1,
    "locktime": 0,
    "vin": [
        {
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "vout": 4294967295,
            "scriptsig": "03233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100",
            "scriptsig_asm": "OP_PUSHBYTES_3 233708 OP_PUSHBYTES_24 4d696e656420627920416e74506f6f6c373946205b8160a4 OP_PUSHBYTES_37 6c0000946e0100",
            "witness": [
                "0000000000000000000000000000000000000000000000000000000000000000"
            ],
            "is_coinbase": true,
            "sequence": 4294967295
        }
    ],
    "vout": [
        {
            "scriptpubkey": "00143b821fecac837bd5e3773a6568eb301ccfafe3e1",
            "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 3b821fecac837bd5e3773a6568eb301ccfafe3e1",
            "scriptpubkey_type": "v0_p2wpkh",
            "scriptpubkey_address": "bc1q8wpplm9vsdaatcmh8fjk36esrn86lclp60dlnx",
            "value": 0
        },
        {
            "scriptpubkey": "",
            "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_32 aa21a9ed+merkleroot",
            "scriptpubkey_type": "v0_p2wsh",
            "scriptpubkey_address": "bc1qej6dxtvr48ke9d724pg80522f6d5e0dk5z7a6mzmfl5acaxn6tnsgpfr4k",
            "value": 0
        }
    ]
}"#;

    serde_json::from_str(&txn).unwrap()
}
