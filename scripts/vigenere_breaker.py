#!/usr/bin/env python3
import argparse
import sys

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    if not key:
        raise ValueError("Key must be non-empty")
    out = []
    key = key.lower()
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            k = ord(key[ki % len(key)]) - ord('a')
            if ch.islower():
                base = ord('a')
                dec = (ord(ch) - base - k) % 26 + base
                out.append(chr(dec))
            else:
                base = ord('A')
                dec = (ord(ch) - base - k) % 26 + base
                out.append(chr(dec))
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)

def main():
    p = argparse.ArgumentParser(description='Simple Vigenere decryptor')
    p.add_argument('ciphertext', nargs='?', help='Cipher text to decrypt')
    p.add_argument('-k','--key', help='Vigenere key (letters only)')
    args = p.parse_args()

    if not args.ciphertext:
        print('Provide ciphertext as argument or pipe it in.', file=sys.stderr)
        p.print_help()
        sys.exit(1)

    key = args.key or ''
    if not key:
        print('No key provided. Use -k to pass a key.', file=sys.stderr)
        p.print_help()
        sys.exit(1)

    plaintext = vigenere_decrypt(args.ciphertext, key)
    print(plaintext)

if __name__ == '__main__':
    main()
