#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py "coach+username+100.00"
# or select "Bleichenbacher" from the VS Code debugger

from roots import *

import hashlib
import sys


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    ASN1 = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

    key_length = 2046
    block = b'\x00\x01\xff\x00' + ASN1 + bytes.fromhex(hashlib.sha256(message.encode('utf-8')).hexdigest())
    garbage = (((key_length+2) // 8) - len(block)) * b'\xff'
    block += garbage

    pre_encrypt = bytes_to_integer(block)

    forged_signature = integer_nthroot(pre_encrypt, 3)[0]
    print(bytes_to_base64(integer_to_bytes(forged_signature, 256)))


if __name__ == '__main__':
    main()

