# objective: process transactions, validate them, mine them to a block
# input: ./mempool
# output: output.txt

# difficulty target: 0000ffff00000000000000000000000000000000000000000000000000000000

# output format:
# block header
# serialized coinbase transaction
# txids of the transactions mined in the block

import json
import os
import hashlib

from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigdecode_der

def serialize_transaction(transaction):
    prevout = transaction['vin'][0]['prevout']
    scriptpubkey_type = prevout['scriptpubkey_type']

    if scriptpubkey_type == 'v0_p2wpkh':
        serialized_tx = f"{prevout['value']}{prevout['scriptpubkey']}"
    else:
        serialized_tx = json.dumps(transaction, sort_keys=True)

    return serialized_tx

def double_hash256(data):
    return hashlib.sha256(hashlib.sha256(data.encode()).digest()).digest()

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

    txid = vin['txid']
    signature_hex = vin['witness'][0]
    public_key_hex = vin['witness'][1]

    sighash_type = signature_hex[-2:]
    signature_bytes = bytes.fromhex(signature_hex[:-2])
    
    serialized_tx = serialize_transaction(transaction)
    serialized_tx += sighash_type
    
    message_hash = double_hash256(serialized_tx)
    
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
    return vk.verify(signature_bytes, message_hash, sigdecode=sigdecode_der)
  except (KeyError, ValueError, BadSignatureError, IndexError):
    return False

def mine_block(transactions, difficulty_target):
    block_data = "".join(tx['id'] for tx in transactions)
    nonce = 0
    while True:
        block_header = f'{block_data}{nonce}'
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
            f.write(f"{tx['id']}\n")

def main():
    mempool_dir = "mempool"
    transactions = load_transactions(mempool_dir)
    difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000"
    _, block_hash = mine_block(transactions, difficulty_target)
    write_output(block_hash, transactions)

if __name__ == "__main__":
    main()
    