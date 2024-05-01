# objective: process transactions, validate them, mine them to a block
# input: ./mempool
# output: output.txt

# difficulty target: 0000ffff00000000000000000000000000000000000000000000000000000000

# output format:
# first line: block header
# second line: serialized coinbase transaction
# following lines: txids of the transactions mined in the block

# task 1: process the transactions
# task 2: validate the transactions
# task 3: put the transactions in a block
# task 4: mine the block

import json
import os
import hashlib
import time
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigdecode_der

def load_transactions(mempool_dir):
    transactions = []
    for filename in os.listdir(mempool_dir):
        if filename.endswith('.json'):
            with open(os.path.join(mempool_dir, filename), 'r') as file:
                try:
                    transaction = json.load(file)
                    if validate_transaction(transaction):
                        transactions.append(transaction)
                except json.JSONDecodeError:
                    continue
    return transactions

def validate_transaction(transaction):
    try:
        vin = transaction['vin'][0]
        if 'witness' not in vin or len(vin['witness']) < 2:
            return False

        signature_hex = vin['witness'][0]
        public_key_hex = vin['witness'][1]

        signature_bytes = bytes.fromhex(signature_hex)
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        serialized_tx = serialize_transaction(transaction)
        message_hash = double_hash256(serialized_tx)

        return vk.verify(signature_bytes, message_hash, sigdecode=sigdecode_der)
    except (KeyError, ValueError, BadSignatureError, IndexError):
        return False

def serialize_transaction(transaction):
    # Simplified serialization logic
    serialized_tx = json.dumps(transaction, sort_keys=True)
    return serialized_tx

def double_hash256(data):
    return hashlib.sha256(hashlib.sha256(data.encode()).digest()).digest()

def calculate_merkle_root(transactions):
    if not transactions:
        return ''
    
    tx_hashes = [hashlib.sha256(json.dumps(tx).encode()).hexdigest() for tx in transactions]
    while len(tx_hashes) > 1:
        new_level = []
        for i in range(0, len(tx_hashes), 2):
            left = tx_hashes[i]
            right = tx_hashes[i + 1] if (i + 1) < len(tx_hashes) else tx_hashes[i]
            new_level.append(hashlib.sha256((left + right).encode()).hexdigest())
        tx_hashes = new_level
    
    return tx_hashes[0]

def create_block_header(transactions, nonce):
    merkle_root = calculate_merkle_root(transactions)
    timestamp = int(time.time())
    previous_block_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    version = 1
    bits = '1d00ffff'
    header = f"{version}{previous_block_hash}{merkle_root}{timestamp}{bits}{nonce}"
    return header

def mine_block(transactions, difficulty_target):
    nonce = 0
    while True:
        block_header = create_block_header(transactions, nonce)
        block_hash = hashlib.sha256(block_header.encode()).hexdigest()
        if block_hash < difficulty_target:
            break
        nonce += 1
    return nonce, block_hash

def write_output(block_hash, transactions):
    with open("output.txt", "w") as f:
        f.write(f"Block Hash: {block_hash}\n")
        f.write("Serialized Coinbase Transaction\n")
        for tx in transactions:
            f.write(f"{tx['txid']}\n")

def main():
    mempool_dir = "./mempool"
    transactions = load_transactions(mempool_dir)
    if not transactions:
        print("No valid transactions found.")
        return
    difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000"
    nonce, block_hash = mine_block(transactions, difficulty_target)
    write_output(block_hash, transactions)

if __name__ == "__main__":
    main()
