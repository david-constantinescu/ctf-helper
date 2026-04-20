#!/usr/bin/env python3
"""
number_decoder.py — Decode numeric arrays and encodings common in CTF.
Handles: ASCII decimal arrays, binary strings, octal arrays, phone keypad,
         NATO phonetic, Braille (unicode), pigpen-like numeric ciphers.
Usage: python3 number_decoder.py "<input>"
       echo "72 101 108 108 111" | python3 number_decoder.py -
"""

import sys
import re
import argparse


FLAG_RE = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)


PHONE_KEYPAD = {
    '2': 'ABC', '3': 'DEF', '4': 'GHI', '5': 'JKL',
    '6': 'MNO', '7': 'PQRS', '8': 'TUV', '9': 'WXYZ',
}

NATO = {
    'ALPHA':'A','BRAVO':'B','CHARLIE':'C','DELTA':'D','ECHO':'E',
    'FOXTROT':'F','GOLF':'G','HOTEL':'H','INDIA':'I','JULIET':'J',
    'KILO':'K','LIMA':'L','MIKE':'M','NOVEMBER':'N','OSCAR':'O',
    'PAPA':'P','QUEBEC':'Q','ROMEO':'R','SIERRA':'S','TANGO':'T',
    'UNIFORM':'U','VICTOR':'V','WHISKEY':'W','XRAY':'X','X-RAY':'X',
    'YANKEE':'Y','ZULU':'Z',
}

MORSE = {
    '.-':'A','-.':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
    '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
    '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
    '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
    '-....':'6','--...':'7','---..':'8','----.':'9','-----':'0',
}

BRAILLE_MAP = {
    '⠁':'A','⠃':'B','⠉':'C','⠙':'D','⠑':'E','⠋':'F','⠛':'G','⠓':'H',
    '⠊':'I','⠚':'J','⠅':'K','⠇':'L','⠍':'M','⠝':'N','⠕':'O','⠏':'P',
    '⠟':'Q','⠗':'R','⠎':'S','⠞':'T','⠥':'U','⠧':'V','⠺':'W','⠭':'X',
    '⠽':'Y','⠵':'Z','⠀':' ',
}


def try_ascii_decimal(s):
    """72 101 108 108 111 → Hello"""
    nums = re.findall(r'\b(1[0-1][0-9]|[3-9][0-9]|2[0-9])\b', s)
    if len(nums) < 3:
        return None
    try:
        text = ''.join(chr(int(n)) for n in nums if 32 <= int(n) <= 126)
        if len(text) >= 3:
            return ('ascii_decimal', text)
    except Exception:
        pass
    return None


def try_ascii_decimal_comma(s):
    """72,101,108,108,111 → Hello"""
    if ',' not in s:
        return None
    nums = re.findall(r'\d+', s)
    if len(nums) < 3:
        return None
    try:
        text = ''.join(chr(int(n)) for n in nums if 0 <= int(n) <= 127)
        if len(text) >= 3 and sum(1 for c in text if 32 <= ord(c) <= 126) / len(text) > 0.8:
            return ('ascii_decimal_array', text)
    except Exception:
        pass
    return None


def try_octal(s):
    """101 145 154 154 157 → Hello (octal)"""
    nums = re.findall(r'\b([0-7]{2,3})\b', s)
    if len(nums) < 3:
        return None
    try:
        text = ''.join(chr(int(n, 8)) for n in nums if 0 < int(n, 8) <= 127)
        if len(text) >= 3 and sum(1 for c in text if 32 <= ord(c) <= 126) / len(text) > 0.7:
            return ('octal_array', text)
    except Exception:
        pass
    return None


def try_binary_string(s):
    """01001000 01100101 → He"""
    s = s.replace(' ', '')
    if not re.fullmatch(r'[01]+', s) or len(s) < 8 or len(s) % 8 != 0:
        return None
    try:
        chunks = [s[i:i+8] for i in range(0, len(s), 8)]
        text = ''.join(chr(int(c, 2)) for c in chunks)
        if sum(1 for c in text if 32 <= ord(c) <= 126) / len(text) > 0.8:
            return ('binary_string', text)
    except Exception:
        pass
    return None


def try_phone_keypad(s):
    """222-444-555 → CIL (multi-tap phone)"""
    # Detect pattern: repeated digits separated by spaces/dashes
    tokens = re.findall(r'([2-9])\1*', s.replace(' ', '').replace('-', ''))
    if len(tokens) < 2:
        return None
    result = []
    for tok in tokens:
        digit = tok[0]
        count = len(tok) if isinstance(tok, str) else 1
        # Original re.findall returns strings
        full_tok = re.search(rf'{digit}+', s)
        if full_tok:
            count = len(full_tok.group())
            chars = PHONE_KEYPAD.get(digit, '')
            if chars:
                idx = (count - 1) % len(chars)
                result.append(chars[idx])
    if result:
        return ('phone_keypad_multitap', ''.join(result))
    return None


def try_nato(s):
    """ALPHA BRAVO → AB"""
    words = re.findall(r'\b[A-Z]{4,}\b', s.upper())
    if len(words) < 2:
        return None
    chars = [NATO.get(w) for w in words]
    if any(c is None for c in chars):
        return None
    return ('nato_phonetic', ''.join(chars))


def try_morse(s):
    """.- -... → AB"""
    for sep in (' / ', ' | ', '\n', '  '):
        word_sep = sep.strip() or '/'
        words = s.split(word_sep) if word_sep in s else [s]
        result = []
        for word in words:
            chars = re.split(r'\s+', word.strip())
            decoded_word = ''.join(MORSE.get(c.strip(), '?') for c in chars if c.strip())
            if '?' not in decoded_word:
                result.append(decoded_word)
        if result and all('?' not in w for w in result):
            return ('morse', ' '.join(result))
    return None


def try_braille(s):
    if not any(c in BRAILLE_MAP for c in s):
        return None
    result = ''.join(BRAILLE_MAP.get(c, c) for c in s)
    if result != s:
        return ('braille', result)
    return None


def try_spreadsheet_column(s):
    """A=1, Z=26, AA=27 — sometimes used for numeric encodings"""
    nums = re.findall(r'\b([1-9][0-9]?|1[01][0-9]|12[0-6])\b', s)
    if len(nums) < 3:
        return None
    try:
        text = ''.join(chr(int(n) + 64) for n in nums if 1 <= int(n) <= 26)
        if len(text) == len(nums):
            return ('a1z26', text)
    except Exception:
        pass
    return None


DECODERS = [
    ('Braille',             try_braille),
    ('NATO phonetic',       try_nato),
    ('Morse code',          try_morse),
    ('Binary string',       try_binary_string),
    ('ASCII decimal (CSV)', try_ascii_decimal_comma),
    ('ASCII decimal',       try_ascii_decimal),
    ('Octal array',         try_octal),
    ('A1Z26',               try_spreadsheet_column),
    ('Phone keypad',        try_phone_keypad),
]


def main():
    ap = argparse.ArgumentParser(description="Numeric/Symbolic Decoder for CTF")
    ap.add_argument("input", help="Encoded string, or '-' for stdin")
    args = ap.parse_args()

    raw = sys.stdin.read().strip() if args.input == '-' else args.input

    print(f"[*] Input: {raw[:200]}")
    print("=" * 60)

    found_any = False
    for name, decoder in DECODERS:
        result = decoder(raw)
        if result:
            enc_name, decoded = result
            print(f"[+] {name}: {decoded[:200]}")
            flag = FLAG_RE.search(decoded)
            if flag:
                print(f"  [!!!] FLAG: {flag.group()}")
            found_any = True

    if not found_any:
        print("[*] No numeric/symbolic encoding detected")
        print("[?] Try: decode_all.py, layer_decoder.py, or freq_analysis.py")


if __name__ == "__main__":
    main()
