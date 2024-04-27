# Dhruv Bhanushali | Summer of bitcoin Assignment
This document describes the design approach, implementation details, results, and performance of the block construction program, along with a conclusion and references.

### Design Approach
- The block construction program follows these key steps to create a valid block, 

The key concepts which need to be implemented to create a valid block are:

1. Transaction Selection:

    - Read transactions from the mempool directory.
    - Validate each transaction based on scriptPubKey types (currently supports v0_p2wpkh and p2pkh).
    - Select transactions that fit within the block weight limit while maximizing the total fees collected.

2. Transaction Validation (for the above process)
    - These functions handle verifying a given transaction's validity by creating a sighash or preimage and then checking if the signature is valid or not



3. Coinbase Transaction Construction:

    - Create a coinbase transaction that includes the block reward and a witness commitment.
    - The witness commitment is a hash that includes the Merkle root to link the coinbase transaction to the block.



4. Merkle Root Calculation:

    - The Merkle root is a cryptographic hash that ensures the integrity of the transactions within the block.
    - It's calculated by recursively hashing pairs of transactions and hashing the final result until a single hash remains.

5. Block Header Creation:

    - Set the block version, previous block hash (initially set to zeroes for the genesis block), Merkle root (calculated from the selected transactions), timestamp, and target difficulty.
    - Mine the header by finding a hash value below the target difficulty. This is achieved through a loop that iterates over different nonce values and checks if the resulting hash meets the criteria.

After going through all these steps, we will get a list of all the transactions that are put, the block header and coinbase transaction, now we put them in the specified format on the output file


### Implementation Details

The provided code utilizes several functions to achieve these steps. Here's a breakdown of the key functions and their logic:

#### Main Function

1. **block_maker** : 
    -  This function orchestrates the entire block creation process.
    - It calls functions to read transactions, select valid transactions, create the block header, construct the coinbase transaction, calculate Merkle roots, and finally write the block data to a file.
2. **read_transactions**:
    -  This function reads all JSON files from the specified mempool directory and stores them as strings.
3. **transaction_selector**:
    - This function iterates through the transactions, performs validation checks, and selects transactions that fit within the block weight limit while maximizing the total fees.
4. **create_block_header**:
    - This function creates the block header by setting predefined values for version, previous hash (except for the genesis block), and using functions to get the current timestamp, target difficulty, and Merkle root from transactions. It then uses a loop to mine the header until a valid hash is found.
5. **create_coinbase**:
    - This function constructs the coinbase transaction by setting the block reward in the first output and calculating the witness commitment based on the Merkle root. It then serializes the transaction.
6. **create_merkle_root**: 
    - This function implements the Merkle tree algorithm. It iteratively hashes pairs of transaction hashes until a single hash (Merkle root) remains.
7. **hash256**:
    - This function performs double SHA-256 hashing on a provided data byte vector.

#### Transaction Validation

The program incorporates functions to validate transactions based on their type:

1. **validate_legacy**:
    - This function handles transactions using legacy (non-SegWit) scriptPubKey types. It iterates through each input, extracts the signature and public key, calculates the sighash using the generate_sighash_legacy function, and finally uses the verify_signature function to validate the signature with the public key.

2. **validate_segwit**:
    - This function handles transactions using SegWit (Segregated Witness) scriptPubKey types. It checks for the scriptPubKey type and if it's v0_p2wpkh (pay to witness pubkey hash), it extracts the signature and public key from the witness field. It then calculates the preimage hash using the generate_preimage_segwit function and the reusables created by create_reusables, and finally uses the verify_signature function for validation. Otherwise, it falls back to legacy scriptPubKey validation using generate_sighash_legacy.

3. **verify_signature**:
    - This function takes the message hash, public key, and signature as input and uses the secp256k1 library to verify the signature using Elliptic Curve Digital Signature Algorithm (ECDSA).

#### Block Serialization

The block serialization process involves converting the block structure into a byte stream for storage or transmission. Here are the relevant functions:

1. **serialize_block_header**:
    - This function takes a block header object and serializes its components (version, hash, Merkle root, timestamp, difficulty, nonce) into a byte stream using little-endian byte ordering.

2. **serialize_transaction**:
    - This function takes a transaction object and serializes its components (version, inputs, outputs, locktime) into a byte stream. It handles witness data differently depending on whether the transaction is a regular transaction or a SegWit transaction.
        - Regular Transaction: The witness data is an empty string.
        - SegWit Transaction: The function uses serialize_witness to serialize the witness data separately and combines it with the serialized transaction data.

3. **serialize_witness**:
    - This function takes a witness object (an array of witness elements) and serializes it by encoding the number of elements and then encoding each element as a byte stream.

Finally, the program writes the serialized block header, serialized coinbase transaction, and serialized transaction IDs to an output file

### Results and Performance

The program successfully creates a valid block structure considering the provided logic and incorporates transaction validation for both legacy and SegWit transactions. However, performance optimization can be implemented for certain functionalities:

- Transaction Validation: Currently, each transaction goes through individual scriptPubKey type checks. This can be optimized by implementing a lookup table for faster validation.

- Merkle Root Calculation: While the Merkle tree approach ensures data integrity, for a large number of transactions, it can become computationally expensive. Alternative approaches like using optimized hashing algorithms or parallelization techniques can be explored.

## Conclusion
- By solving the assignment i have understood in great technical depth regarding how each how to aspects of block making works, the validation and serialzation functions were the most difficult to implement, but i learnt a great deal about how signatures are validated and how we create the message for signing, overall the assignment pushed me to know very minute details, even missing a minor detail make block invalid..
This assignment covered the mining part but still i dont have hands on experience with the network part of bitcoin, which is what i want to explore in the future..

## References

whitepaper -> https://bitcoin.org/bitcoin.pdf

Rust documentation -> https://www.rust-lang.org/learn

Learn me a bitcoin ->  https://learnmeabitcoin.com/ (really helpful, has covered almost all aspects in great detail)

Other than these minor problems were covered from the forums(reddit, bitcoin wiki & stack overflow)


