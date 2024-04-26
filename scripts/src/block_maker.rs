// keeps the basic functions and types that are making the blocks

// use std::fs;

// use crate::verification;

use core::hash;
use std::{
    fmt::format, fs, io::{self, Bytes, Read, Write}, iter::OnceWith, string, time::{SystemTime, UNIX_EPOCH}, vec
};

use ripemd::digest::InvalidOutputSize;
use secp256k1::ffi::NonceFn;
use serde_json::{value::Index, Value};
use sha2::{Digest, Sha256};

use crate::{serialization, validation};

// // fn return_txns() -> Vec<String> {
//     let txns: Vec<&str> = vec![
//         "18e754e68c4034ff3f8be1472a7df56b827394de995298918ca0ec4c64ee4a57",
//         "74b2636857dc6c625a256e0545f4424258d2faa6605d14d652d49f8eb769f84f",
//         "229beea8b9cbf1cb3b0b1a82bdb56927d634132a0a0eb6cf4db1166e770c8e6d",
//         "3ae0464e3ca5b698baf181cce242f858016dae022f024ed1dd36b5f562fd46b8",
//         "c55ed67eb7a6d96f8d49c9bfe02279b03b3d0b70aefca3391aa4d3992e4133a8",
//         "ebe0bf8e7ea875f2882002398cdbe34b66dde50e116201a1e5561e3f40d60153",
//         "d2d468350ad39c079d60c3207dea7615c3c39da55d2406e65f343cd772fa207f",
//         "502be4d8dabb3e265750e4ca32d31bb90bc478369905a667331f492300154dbf",
//         "4a27fbb6798f19091356dcad8636608f16f33c5a77b89fbda3e1008402643036",
//         "34978d261bdeb1894db852a8da7f755c44762554644f4ae7ea72fc75d58315fe",
//         "38945760c53da813a338f70db455fb09773746e2e8f440156cf2b2cf7e2f48d3",
//         "2a335d82bf56117d05ca9cdc6f13d9778f2acaa6aab877ac63bf878f1a8f7419",
//         "1662dde54f12b881ac3f84ab08395f54c606ddf58b1d4f283af72a2b4cb80e70",
//         "afada8c5228d9dd575973db93be427db3bb57171896f252fd1a5daff04ee76a9",
//         "c210e0e1645aed2fc0ba90bff09110a4abb7fcb8ecaf9b3d8fc2e1729b2c4ea2",
//         "69759426610a8d7ac8bda865813b19a8d8d50e402aef3cde5a13ce7150b63806",
//         "b23dd1eafccf095aefb2addaee31e0d698a735ee9b071651c78a2dea9982a8e0",
//         "77b1d3101840f7e83aa02ca567cd172f047c925c3b50ec59a499c98036e9b28f",
//         "5f5fffc08fc6e6487c68574116df25a6c58491287b68b6314fea4acf0b9db6d9",
//         "a467179402778286e0375c8d4f27d305261dba6705bb2acb0b4517b28e4781de",
//         "90c4eda2f81e01ca17dd417d19bb6e13f6694826b3dd5d5a61fba7f14a94d437",
//         "a3f625f38f02458058c17fec488d8ac5aaeb02f23cbbde9d7973b4b3c140eaab",
//         "03a0c51bd05ae624900c1498919e4e2e6b48f0c8e773bd2f7ac5316c0c176d6c",
//         "d0d2ea55ebe3b5cdce0c2c5783a5d7789045d0ee1b14e8f437c7dbba9bff3000",
//         "6f2f6e1b668076d279feff1f324989b8eb7e2a4561ee631d5f697077857524c4",
//         "7b5e3d76fe594632e0e86679af4381ef1780517d7d12b3ad87ccab4eead9ce0e",
//         "6a8e9040af88c9535c9a9259d3bd154a2e70b343ad10956c68da96abca24deec",
//         "0dde7e4995bb3d57fcd6d9e62879a89c0100c5128c58053d1e3fd50960fdf673",
//         "6bc78987b18e88a1ff2b8e4e335a516edbe0938e58d15c98cb4b78d09d389f1b",
//         "4860cc5a9a8c4b1942632a26ac90bac9404fd36f6879958feeb16b3ed721155b",
//         "64274bc522a46965ff5aded2d1f3e1d085fbb479ba1f82f6d7f88f2ed065696c",
//         "ec761241332a0b782f69e85efce17a7bf8dcba7d41a7db59fff6315d98f4af8e",
//         "9fa0a908e0d7388c2e76ee604a97528a1c340649f9cddfae57e623f6f81e0d62",
//         "005ccdb46d7a79747723887e7402db5de36a3b883449ad3a538dd3edb239cbba",
//         "54a4c8490bdee769c11a1f0ada8fcdeb5b4e1500bfd8aa4155cc41fd2d62aaa4",
//         "94b51bd416e40673d7ed567b8e321d717b41ddd95376fb2d9dd011cd06a13078",
//         "28e122fd2dcbd7f1cb0415c0caaf909b21e33c45fed3caaf0196626db172382b",
//     ];

//     //convert all to string
//     txns.iter()
//         .map(|&s| {
//             let mut bytes = hex::decode(s).unwrap();
//             bytes.reverse();
//             hex::encode(bytes)
//         })
//         .collect()
// }

pub(crate) fn block_maker() {
    use std::time::Instant;

    let now = Instant::now();

    let mut transactions_json = read_trasactions();
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
    wtxids.insert(0,"0000000000000000000000000000000000000000000000000000000000000000".to_string());

    for wtxid in &wtxids {
        let mut txid_bytes = hex::decode(wtxid).unwrap();
        txid_bytes.reverse();
        println!("{}", hex::encode(txid_bytes));
    }

    let merkle_wtxid = create_merkle_root(&wtxids);

    println!("merkle_wtxid root -> {}", merkle_wtxid);
    let coinbase_txn = create_coin_base(&merkle_wtxid, &transactions.2);
    println!("Coinbase: {}", coinbase_txn.0);
    transactions.0.insert(0, coinbase_txn.clone().0);

    //create txid from
    txids.insert(0, serialization::txid_maker(coinbase_txn.clone().0));

    //create merkle root
    let merkle_txid = create_merkle_root(&txids);
    for txid in &txids {
        let mut txid_bytes =    hex::decode(txid).unwrap();
        txid_bytes.reverse();
        println!("{}", hex::encode(txid_bytes));
    }
    println!("Merkle_txid = {}", merkle_txid);

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
    let version = "04000000"; //little endian hex
    let prevous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"; //32 bytes of zeroes
    let time = get_time(); //"662aad6e"; //unix timestamp
    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let bits = "ffff001f"; //target

    // let nonce = "42a14695"; //random number
    let header = format!(
        "{}{}{}{}{}",
        version, prevous_block_hash, merkle_root, time, bits
    );
    let header = mine_header(&target, header);
    println!("header => {}", header);
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
    let mut target_bytes = hex::decode(target).expect("Target invalid");
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
    // let path = "../mempool";
    // let directory = fs::read_dir(path).unwrap();

    let mut txvec: Vec<String> = vec![];
    let mut wtxvec: Vec<String> = vec![];
    let mut weight: usize = 0;
    let mut bytes: usize = 0;
    let mut total_fees: usize = 0;

    for transaction in txns {
        let tx: Value = serde_json::from_str(&transaction).expect("Error parsing JSON");

        if !check_p2wpkh_pkh(&tx) {
            continue;
        }
        if !validation::validate_segwit(&tx) {
            continue;
        }
        let serialized_tx = serialization::serializer(&tx);
        let fees = calculate_fees(tx);
        let txwt = calculate_weight(&serialized_tx.1, &serialized_tx.2);
        if weight + txwt < 10000 - 1000  {
        // if weight + txwt < 4000 {
            //push the txndata and witness data to the txvec
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

pub(crate) fn check_p2wpkh_pkh(txn: &serde_json::Value) -> bool {
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
    println!("Witness commitment => {}", witness_commitment);
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

fn create_header() -> String {
    let version = "01000000"; //little endian hex

    let previous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000";

    todo!()
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
