#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "http://cpsc4200.mpese.com/username/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
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

def padding_oracle_attack(ciphertext, oracle_url):
    fake = [0] * 16
    plaintext = [0] * 16
    block_size = 16

    num_blocks = int(len(ciphertext) / block_size)
    blocks =  [[]] * num_blocks
    new_plaintext = b""

    for i in range(num_blocks):
        blocks[i] = ciphertext[i * block_size: (i + 1) * block_size]

    for j in range(len(blocks) - 1):
        for idx in range(1, 17):
            candidates = []
            for x in range(256):
                fake[-idx] = x
                
                modified_block = bytes(fake) + blocks[j + 1]
                candidates.append(modified_block)
                
            responses = oracle(oracle_url, candidates)
            for x in range(256):
                if responses[x]["status"] == "invalid_mac":
                    plaintext[-idx] = x ^ idx ^ blocks[j][-idx]
                    break

            for a in range(1, idx + 1):
                fake[-a] = plaintext[-a] ^ idx + 1 ^ blocks[j][-a]
        
        new_plaintext += bytes(plaintext)

    return new_plaintext

def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)

    decrypted = padding_oracle_attack(message, oracle_url)
    decrypted = decrypted[:-(decrypted[-1])]
    final_decrypted = decrypted[:-32]
    print(final_decrypted.decode('utf-8'))


if __name__ == '__main__':
    main()

