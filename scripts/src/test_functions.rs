use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

use crate::{block_maker, serialization};
use crate::validation::{validate_legacy, validate_segwit};

pub(crate) fn _test_serialization() {
    let path = "../mempool2";
    let mempool = fs::read_dir(path).unwrap();
    for transaction in mempool {
        let transaction = transaction.expect("Unable to read directory transaction");
        if transaction.path().is_file() {
            // then give the file to the transaction processor
            // transaction_processor(path, &mut writer, &name)?;
            let path = transaction.path();
            let name = transaction.file_name();
            let filename = name.to_str().unwrap();

            //read the transaction from the file
            let mut file = std::fs::File::open(path).expect("File not found");
            let mut tx_data = String::new();
            file.read_to_string(&mut tx_data)
                .expect("Error reading file");

            let txn: serde_json::Value = serde_json::from_str(&tx_data).expect("Error parsing JSON");

            let serialized_tx = serialization::serializer(&txn);

            let txid = serialization::txid_maker(serialized_tx.1.clone());
            let wtxid = serialization::txid_maker(serialized_tx.0.clone());

            let mut txid_bytes = hex::decode(&txid).unwrap();
            txid_bytes.reverse();

            let mut hasher = Sha256::new();
            hasher.update(txid_bytes);
            let result = hasher.finalize();
            let result = hex::encode(result);

            println!("FilenameDerived: {}", result);
            println!("Filename: {}", filename);
            println!("TXID: {}", txid);
            println!("WTXID: {}", wtxid);
            println!("Serialized Transaction: {:?}", serialized_tx.0);
        }
    }
}

pub(crate) fn _validate_all_p2pkh() {
    let path = "../mempool2";
    let mempool = fs::read_dir(path).unwrap();

    let mut count_p2pkh = 0;
    let mut count_valid = 0;

    for transaction in mempool {
        let transaction = transaction.expect("Unable to read directory transaction");
        if transaction.path().is_file() {
            let path = transaction.path();
            let mut file = std::fs::File::open(path).expect("File not found");
            let mut tx_data = String::new();
            file.read_to_string(&mut tx_data)
                .expect("Error reading file");

            let txn: serde_json::Value =
                serde_json::from_str(&tx_data).expect("Error parsing JSON");
            if _check_p2pkh(txn) {
                count_p2pkh += 1;
                if validate_legacy(&tx_data) {
                    count_valid += 1;
                }
            };
        }
    }
    println!("Total P2PKH Transactions: {}", count_p2pkh);
    println!("Valid P2PKH Transactions: {}", count_valid);
}

pub(crate) fn _validate_all_p2wpkh() {
    let path = "../mempool2";
    let mempool = fs::read_dir(path).unwrap();

    let mut count_p2wpkh = 0;
    let mut count_valid = 0;

    for transaction in mempool {
        let transaction = transaction.expect("Unable to read directory transaction");
        if transaction.path().is_file() {
            // then give the file to the transaction processor
            // transaction_processor(path, &mut writer, &name)?;
            //read the transaction from the file
            let path = transaction.path();
            let mut file = std::fs::File::open(path).expect("File not found");
            let mut tx_data = String::new();
            file.read_to_string(&mut tx_data)
                .expect("Error reading file");

            let txn: serde_json::Value =
                serde_json::from_str(&tx_data).expect("Error parsing JSON");
            if block_maker::check_p2wpkh_pkh(&txn) {
                count_p2wpkh += 1;
                if validate_segwit(&txn) {
                    count_valid += 1;
                }
            };
        }
    }
    println!("Total P2WPKH & P2PKH Transactions: {}", count_p2wpkh);
    println!("Valid P2WPKH & P2PKH Transactions: {}", count_valid);

}

fn _reverse_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut reversed_bytes = vec![];
    for byte in bytes.iter().rev() {
        reversed_bytes.push(*byte);
    }
    reversed_bytes
}

fn _check_p2pkh(txn: serde_json::Value) -> bool {
    //check if all inputs are p2pkh
    for input in txn["vin"].as_array().unwrap() {
        if input["prevout"]["scriptpubkey_type"].as_str().unwrap() != "p2pkh" {
            return false;
        } else {
            continue;
        }
    }
    true
}

fn _check_p2wpkh(txn: serde_json::Value) -> bool {
    //check if all inputs are p2wpkh
    for input in txn["vin"].as_array().unwrap() {
        if input["prevout"]["scriptpubkey_type"].as_str().unwrap() != "v0_p2wpkh" {
            return false;
        } else {
            continue;
        }
    }
    true
}
