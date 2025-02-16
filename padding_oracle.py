#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "http://cpsc4200.mpese.com/username/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
import hmac
import hashlib
from typing import Union, Dict, List

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue

def padding_oracle_attack(ciphertext: bytes, oracle_url: str) -> bytes:
    block_size = 16
    num_blocks = len(ciphertext) // block_size
    blocks = [ciphertext[i * block_size: (i + 1) * block_size] for i in range(num_blocks)]
    
    new_plaintext = bytearray()

    for j in range(num_blocks - 1):
        plaintext = bytearray(block_size)
        for idx in range(1, block_size + 1):
            for x in range(256):
                fake = bytearray(block_size)
                fake[-idx] = x

                for a in range(1, idx):
                    fake[-a] = plaintext[-a] ^ idx + 1 ^ blocks[j][-a]

                modified_block = fake + blocks[j + 1]

                response = oracle(oracle_url, [modified_block])
                if response[0]["status"] == "invalid_mac":
                    plaintext[-idx] = x ^ idx ^ blocks[j][-idx]
                    break

        new_plaintext.extend(plaintext)

    return bytes(new_plaintext)

def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)


    decrypted_message = padding_oracle_attack(message, oracle_url)
    decrypted = decrypted_message.decode('utf-8')
    print(decrypted)


if __name__ == '__main__':
    main()

