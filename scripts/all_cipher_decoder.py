#!/usr/bin/env python3
"""
Universal Cipher Decoder - Attempts to decode text using various ciphers and encodings.
v2 - Uses AI to filter results.
"""

import argparse
import base64
import binascii
import string
import re
import sys
from urllib.parse import unquote
import html
from collections import Counter
import codecs
import json

# Try to import gradio_client, warn if missing
try:
    from gradio_client import Client
except ImportError:
    print("Error: gradio_client is not installed. Please run: pip install gradio_client")
    sys.exit(1)


class CipherDecoder:
    def __init__(self, password=None):
        self.password = password
        self.results = []
        # Common English words for detection (kept in case needed later, but unused for filtering in v2)
        self.common_words = {
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
            'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
            'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
            'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
            'is', 'was', 'are', 'been', 'has', 'had', 'were', 'said', 'can', 'may'
        }

    def is_readable(self, text):
        """
        Check if text appears to be readable.
        v2 Update: Removed strict English/readability heuristics.
        Retaining only basic validity checks to allow AI to filter.
        """
        if not text:
            return False
            
        # Allow almost anything that isn't empty, so the AI can decide.
        # We strip whitespace to ensure it's not just spaces.
        if len(text.strip()) < 1:
            return False
            
        return True

    def try_base64(self, encoded):
        """Try Base64 decoding."""
        try:
            # Add padding if needed
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            if self.is_readable(decoded):
                self.results.append(('Base64', decoded))
        except:
            pass

    def try_base32(self, encoded):
        """Try Base32 decoding."""
        try:
            # Add padding if needed
            missing_padding = len(encoded) % 8
            if missing_padding:
                encoded += '=' * (8 - missing_padding)
            decoded = base64.b32decode(encoded.upper()).decode('utf-8', errors='ignore')
            if self.is_readable(decoded):
                self.results.append(('Base32', decoded))
        except:
            pass

    def try_base16(self, encoded):
        """Try Base16/Hex decoding."""
        try:
            # Remove common hex prefixes
            clean = encoded.replace('0x', '').replace('\\x', '').replace(' ', '')
            decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
            if self.is_readable(decoded):
                self.results.append(('Base16/Hex', decoded))
        except:
            pass

    def try_url_decode(self, encoded):
        """Try URL decoding."""
        try:
            decoded = unquote(encoded)
            # Check if decoded is different, or if we just want to collect everything.
            # Keeping the "decoded != encoded" check is probably fine to avoid duplicates,
            # but for v2 we want robustness, so we'll allow it if it changed.
            if decoded != encoded and self.is_readable(decoded):
                self.results.append(('URL Encoding', decoded))
        except:
            pass

    def try_html_decode(self, encoded):
        """Try HTML entity decoding."""
        try:
            decoded = html.unescape(encoded)
            if decoded != encoded and self.is_readable(decoded):
                self.results.append(('HTML Entities', decoded))
        except:
            pass

    def try_rot13(self, encoded):
        """Try ROT13 decoding."""
        try:
            decoded = codecs.decode(encoded, 'rot13')
            if self.is_readable(decoded):
                self.results.append(('ROT13', decoded))
        except:
            pass

    def try_caesar_cipher(self, encoded):
        """Try all Caesar cipher shifts (1-25)."""
        for shift in range(1, 26):
            decoded = ''
            for char in encoded:
                if char.isalpha():
                    ascii_offset = ord('A') if char.isupper() else ord('a')
                    decoded += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    decoded += char
            
            if self.is_readable(decoded):
                self.results.append((f'Caesar Cipher (shift {shift})', decoded))

    def try_atbash(self, encoded):
        """Try Atbash cipher."""
        decoded = ''
        for char in encoded:
            if char.isalpha():
                if char.isupper():
                    decoded += chr(ord('Z') - (ord(char) - ord('A')))
                else:
                    decoded += chr(ord('z') - (ord(char) - ord('a')))
            else:
                decoded += char
        
        if self.is_readable(decoded):
            self.results.append(('Atbash Cipher', decoded))

    def try_reverse(self, encoded):
        """Try reversing the text."""
        decoded = encoded[::-1]
        if self.is_readable(decoded):
            self.results.append(('Reversed Text', decoded))

    def try_binary(self, encoded):
        """Try binary to text."""
        try:
            # Remove spaces and ensure it's binary
            clean = encoded.replace(' ', '')
            if all(c in '01' for c in clean) and len(clean) % 8 == 0:
                decoded = ''.join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))
                if self.is_readable(decoded):
                    self.results.append(('Binary', decoded))
        except:
            pass

    def try_octal(self, encoded):
        """Try octal to text."""
        try:
            # Try different octal formats
            parts = encoded.replace('\\', ' ').split()
            decoded = ''.join(chr(int(p, 8)) for p in parts if p.isdigit())
            if decoded and self.is_readable(decoded):
                self.results.append(('Octal', decoded))
        except:
            pass

    def try_morse(self, encoded):
        """Try Morse code decoding."""
        morse_code = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9'
        }
        try:
            # Try space-separated morse
            words = encoded.split('  ')
            decoded = ''
            for word in words:
                for code in word.split():
                    if code in morse_code:
                        decoded += morse_code[code]
                    else:
                        decoded += '?'
                decoded += ' '
            
            if self.is_readable(decoded.strip()):
                self.results.append(('Morse Code', decoded.strip()))
        except:
            pass

    def try_ascii85(self, encoded):
        """Try ASCII85 decoding."""
        try:
            decoded = base64.a85decode(encoded).decode('utf-8', errors='ignore')
            if self.is_readable(decoded):
                self.results.append(('ASCII85', decoded))
        except:
            pass

    def try_xor_simple(self, encoded):
        """Try XOR with common single-byte keys."""
        try:
            data = encoded.encode('latin-1')
            for key in range(1, 256):
                decoded = ''.join(chr(b ^ key) for b in data)
                if self.is_readable(decoded):
                    self.results.append((f'XOR (key: {key})', decoded))
        except:
            pass

    def try_vigenere(self, encoded):
        """Try Vigenère cipher with password."""
        if not self.password:
            return
        
        try:
            decoded = ''
            key = self.password.upper()
            key_index = 0
            
            for char in encoded:
                if char.isalpha():
                    ascii_offset = ord('A') if char.isupper() else ord('a')
                    key_char = key[key_index % len(key)]
                    shift = ord(key_char) - ord('A')
                    decoded += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                    key_index += 1
                else:
                    decoded += char
            
            if self.is_readable(decoded):
                self.results.append(('Vigenère Cipher', decoded))
        except:
            pass

    def try_xor_password(self, encoded):
        """Try XOR with password."""
        if not self.password:
            return
        
        try:
            key = self.password.encode('utf-8')
            data = encoded.encode('latin-1')
            decoded = ''.join(chr(data[i] ^ key[i % len(key)]) for i in range(len(data)))
            if self.is_readable(decoded):
                self.results.append(('XOR with Password', decoded))
        except:
            pass

    def try_fernet(self, encoded):
        """Try Fernet decryption with password."""
        if not self.password:
            return
        
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
            import base64
            
            # Derive key from password
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt',  # In real use, salt should be stored with ciphertext
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
            f = Fernet(key)
            
            decoded = f.decrypt(encoded.encode()).decode('utf-8')
            if self.is_readable(decoded):
                self.results.append(('Fernet (cryptography)', decoded))
        except:
            pass

    def try_aes(self, encoded):
        """Try AES decryption with password."""
        if not self.password:
            return
        
        try:
            from Crypto.Cipher import AES
            from Crypto.Protocol.KDF import PBKDF2
            import base64
            
            # Try to decode from base64 first
            try:
                data = base64.b64decode(encoded)
            except:
                data = encoded.encode('latin-1')
            
            # Derive key from password
            key = PBKDF2(self.password, b'salt', dkLen=32)
            
            # Try AES-ECB
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                if len(data) % 16 == 0:
                    decoded = cipher.decrypt(data).decode('utf-8', errors='ignore').rstrip('\x00')
                    if self.is_readable(decoded):
                        self.results.append(('AES-ECB', decoded))
            except:
                pass
        except ImportError:
            pass  # Crypto library not installed
        except:
            pass

    def decode_all(self, encoded):
        """Try all decoding methods."""
        # Non-password methods
        self.try_base64(encoded)
        self.try_base32(encoded)
        self.try_base16(encoded)
        self.try_url_decode(encoded)
        self.try_html_decode(encoded)
        self.try_rot13(encoded)
        self.try_caesar_cipher(encoded)
        self.try_atbash(encoded)
        self.try_reverse(encoded)
        self.try_binary(encoded)
        self.try_octal(encoded)
        self.try_morse(encoded)
        self.try_ascii85(encoded)
        self.try_xor_simple(encoded)
        
        # Password-based methods (if password provided)
        if self.password:
            self.try_vigenere(encoded)
            self.try_xor_password(encoded)
            self.try_fernet(encoded)
            self.try_aes(encoded)
        
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='Universal Cipher Decoder V2 - Uses AI to filter results (Nymbo/Groq-Gradio).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "SGVsbG8gV29ybGQh"
  %(prog)s "Uryyb Jbeyq" -p mypassword
  %(prog)s -p secret "encrypted_text_here"
        """
    )
    parser.add_argument('encoded', help='The encoded string to decode')
    parser.add_argument('-p', '--password', help='Password for password-based ciphers', default=None)
    
    args = parser.parse_args()
    
    print(f"[*] Attempting to decode: {args.encoded[:50]}{'...' if len(args.encoded) > 50 else ''}")
    if args.password:
        print(f"[*] Using password: {'*' * len(args.password)}")
    print()
    
    decoder = CipherDecoder(password=args.password)
    results = decoder.decode_all(args.encoded)
    
    if not results:
        print("[-] No potential decodings generated.")
        return

    print(f"[*] Generated {len(results)} candidates. Sending to AI for filtering...")
    
    # Prepare message for AI
    candidates_list = []
    for i, (method, decoded) in enumerate(results):
        # Escape newlines or control chars that might break json construction if not careful
        # JSON output request handles this on the API side, but for prompt context:
        clean_decoded = decoded.replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')
        candidates_list.append(f'Method: {method} | Text: "{clean_decoded}"')
    
    candidates_text = "\n".join(candidates_list)
    
    prompt = f"""
I have a list of potential decoded texts from a CTF (Capture The Flag) challenge.
Most of them are likely garbage/incorrect decodings.
Please analyze the list and identify ONLY the ones that look like:
1. Valid English text.
2. Valid Romanian text.
3. Strings related to a CTF flag (e.g., in format flag{{...}} or similar).

Here are the candidates:
{candidates_text}

INSTRUCTIONS:
- Return ONLY a JSON array of strings containing just the valid/interesting decoded texts.
- Do not include the Method name in the output array, just the text content.
- If nothing is found, return an empty array [].
- Do NOT output any markdown code blocks (like ```json), just the raw JSON string.
"""

    try:
        client = Client("Nymbo/Groq-Gradio")
        result = client.predict(
                message=prompt,
                request="llama-3.3-70b-versatile",
                param_3=0.5,
                param_4=8100,
                param_5=0.5,
                param_6=0,
                api_name="/chat"
        )
        
        # Parse output
        # Look for JSON array pattern
        json_match = re.search(r'\[.*\]', result, re.DOTALL)
        
        if json_match:
            try:
                good_decryptions = json.loads(json_match.group(0))
                
                if good_decryptions:
                    print(f"[+] AI Found {len(good_decryptions)} likely matches:\n")
                    for item in good_decryptions:
                        print(f"{'='*70}")
                        print(item)
                        print(f"{'='*70}\n")
                else:
                    print("[-] AI found no interesting matches.")
            except json.JSONDecodeError:
                print("[-] AI returned data but it was not valid JSON.")
                print("Raw response:", result)
        else:
            print("[-] No JSON array found in AI response.")
            print("Raw response:", result)

    except Exception as e:
        print(f"[-] Error querying AI: {e}")

if __name__ == '__main__':
    main()
