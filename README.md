# CTF Helper

A rule-based investigation assistant for Capture The Flag competitions, built around a GUI navigator and a collection of purpose-built Python scripts. No AI, no internet required — competition-legal.

---

## Installation

### Linux / macOS

```bash
git clone https://github.com/david-constantinescu/ctf-helper.git
cd ctf-helper
chmod +x install.sh
./install.sh
```

The installer will:
- Verify Python 3 and tkinter are present
- Install pip dependencies (`Pillow`, `pycryptodome`, `scapy`, `gmpy2`, `pyinstaller`)
- Write a config file at `~/.ctf_navigator.json` pointing to the `scripts/` folder
- Optionally build a standalone executable via `build.sh`

If tkinter is missing on Debian/Ubuntu, it is installed automatically (`sudo apt install python3-tk`). On macOS, install Python from [python.org](https://www.python.org/downloads/) or via `brew install python-tk`.

### Windows

Open **PowerShell** and run:

```powershell
# Allow local scripts to run (one-time, current user only)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

git clone https://github.com/david-constantinescu/ctf-helper.git
cd ctf-helper
.\install.ps1
```

The installer will:
- Verify Python 3 is on PATH (download from [python.org](https://www.python.org/downloads/) — check *Add Python to PATH*)
- Install pip dependencies
- Write a config file at `%USERPROFILE%\.ctf_navigator.json`
- Optionally build a standalone `.exe` via `build.ps1`

---

## Running the Navigator

**From source (any platform):**
```bash
python3 ctf_navigator.py        # Linux / macOS
python  ctf_navigator.py        # Windows
```

**As a standalone executable (after building):**
```bash
./dist/ctf_navigator            # Linux / macOS
dist\ctf_navigator.exe          # Windows — or just double-click it
```

---

## Building the Executable

The build scripts use [PyInstaller](https://pyinstaller.org) to produce a single-file executable with no Python installation required on the target machine.

**Linux / macOS:**
```bash
./build.sh
# Output: dist/ctf_navigator
```

**Windows (PowerShell):**
```powershell
.\build.ps1
# Output: dist\ctf_navigator.exe
```

Both scripts install PyInstaller automatically if it is not already available.

---

## CTF Navigator

`ctf_navigator.py` is a tkinter GUI that acts as an expert system. You add challenge artifacts (files, captures, binaries, encoded strings) and it suggests investigation steps based on what you find, building a branching path through the challenge.

**95 investigation nodes** across 7 categories: Network, Forensics, Stego, Crypto, Rev/Pwn, Web, Misc.

### How it works

1. **Add an artifact** — click *Add Artifact*, browse to your file, or type a name. The type is auto-detected from the file extension or magic bytes.
2. **Suggestion cards appear** — each card shows a description, tool name, a ready-to-copy command with the actual file path substituted in, and practical tips.
3. **Mark results** — click **Hit** if the step found something useful (reveals the next set of follow-up nodes), or **Miss** if it didn't (reveals alternative paths).
4. **Filter by category** — use the category buttons (Network, Crypto, Forensics, etc.) to focus the suggestion panel.
5. **Track your path** — the left panel records every step taken with timestamps.
6. **Export** — export the full investigation path and notes to a text file.

### Artifact types supported

| Icon | Type | Extensions auto-detected |
|------|------|--------------------------|
| 📡 | PCAP / Network capture | `.pcap` `.pcapng` `.cap` |
| 🖼 | Image | `.png` `.jpg` `.jpeg` `.bmp` `.gif` `.tiff` |
| 🎵 | Audio | `.wav` `.mp3` `.ogg` `.flac` |
| 📦 | Archive | `.zip` `.tar` `.gz` `.bz2` `.xz` `.7z` `.rar` |
| ⚙ | ELF binary | magic bytes `\x7fELF` |
| 💻 | Windows executable | `.exe` `.dll` + PE header check |
| 📄 | PDF | `.pdf` |
| 🔤 | Text / encoded string | `.txt` `.log` `.md` |
| 🌐 | Web / URL | manual selection |
| 🐳 | Docker image | manual selection |
| 🧠 | Memory dump | `.dmp` `.raw` `.vmem` `.mem` |
| 🐍 | Python / SageMath | `.py` `.pyw` `.sage` `.sagews` |
| 🟨 | JavaScript / TypeScript | `.js` `.ts` `.jsx` `.tsx` `.mjs` `.cjs` |
| ☕ | Java / JVM | `.jar` `.class` `.java` |
| 🐚 | Shell / Batch script | `.sh` `.bash` `.zsh` `.ps1` `.bat` `.cmd` |
| 🔑 | Certificate / Key | `.pem` `.crt` `.cer` `.key` `.p12` `.pfx` `.der` |
| 🗄 | SQLite database | `.db` `.sqlite` `.sqlite3` |
| 🐘 | PHP script | `.php` `.php7` `.phtml` `.php5` |
| 🦀 | Rust source | `.rs` |
| ❓ | Unknown binary | magic byte fallback |

---

## Scripts

All scripts live in `scripts/`. They are referenced by the navigator's suggestion cards but can also be run standalone from the command line.

The navigator automatically substitutes the script folder path into commands, so you can copy-paste them directly into a terminal.

### Decoders & Deobfuscators

| Script | Usage | What it does |
|--------|-------|-------------|
| `layer_decoder.py` | `python3 layer_decoder.py "<encoded>"` | Recursive multi-layer decoder. Auto-detects and strips base64, base32, base58, hex, gzip/zlib, ROT13, ROT47, URL encoding, HTML entities, unicode escapes, and binary. Loops until no more layers or a flag is found. |
| `decode_all.py` | `python3 decode_all.py "<text>"` | Single-pass universal decoder — tries ROT-N, Base*, XOR, Atbash, hex, reverse, URL encoding, and more simultaneously. |
| `number_decoder.py` | `python3 number_decoder.py "<input>"` | Decodes numeric and symbolic arrays: ASCII decimal (`72 101 108`), binary strings, octal, Morse code, NATO phonetic, Braille, A1Z26, and phone keypad multi-tap. |
| `base_decoder.py` | `python3 base_decoder.py "<text>"` | Auto-detects and decodes Base16, Base32, Base58, Base64, Base85 and common variants. |
| `brute_rot.py` | `python3 brute_rot.py "<text>"` | Tries all ROT-N shifts (ROT-1 through ROT-25) plus ROT-47. |
| `freq_analysis.py` | `python3 freq_analysis.py "<ciphertext>" --digraphs --ioc` | Letter frequency analysis for cracking substitution ciphers. |
| `vigenere_crack.py` | `python3 vigenere_crack.py "<ciphertext>"` | Cracks Vigenère cipher without the key using Kasiski examination and Index of Coincidence. |
| `vigenere_breaker.py` | `python3 vigenere_breaker.py "<ciphertext>" --key KEY` | Vigenère cipher decryption with a known or guessed key. |
| `bacon_cypher_breaker.py` | `python3 bacon_cypher_breaker.py "<AABBA...>"` | Decodes Bacon's cipher (A/B encoding representing A–Z). |
| `all_cipher_decoder.py` | `python3 all_cipher_decoder.py "<text>"` | Universal classical cipher decoder with automatic scoring. |
| `xor_brute.py` | `python3 xor_brute.py <file> [--keylen 1-4]` | Brute-forces single and multi-byte XOR keys against a ciphertext file. |
| `cypher_bruxor.py` | `python3 cypher_bruxor.py "<hex>"` | Simple XOR brute force for short hex-encoded ciphertexts. |
| `ps_deobfuscate.py` | `python3 ps_deobfuscate.py <file.ps1>` | PowerShell deobfuscation: unwraps `-EncodedCommand` base64 (UTF-16LE), `[char]` arrays, `Invoke-Expression`/`IEX` chains, XOR loops, gzip payloads. Recurses through layers. |
| `php_deobfuscate.py` | `python3 php_deobfuscate.py <file.php>` | PHP deobfuscation: strips `base64_decode`/`str_rot13`/`gzinflate` chains, `chr()` concatenation, hex/octal string literals, and nested `eval()` calls. |
| `js_deobfuscate.py` | `python3 js_deobfuscate.py <file.js> [--decode-strings] [--beautify]` | JavaScript deobfuscation: detects and decodes `eval(atob(...))`, `String.fromCharCode()` arrays, `\x` hex escapes, and `_0xNNNN` hex-array patterns. Optional basic beautification. |

### Cryptography

| Script | Usage | What it does |
|--------|-------|-------------|
| `rsa_attack.py` | `python3 rsa_attack.py --n N --e E --c C` | Common RSA attacks: Fermat factorisation (works when p ≈ q), Wiener's theorem (small d), small-exponent direct root (e=2,3), and common-factor GCD between multiple moduli. Loads modulus from PEM with `--pubkey cert.pem`. |
| `cert_inspector.py` | `python3 cert_inspector.py <file.pem>` | Parses PEM/DER certificates and key files. Extracts RSA/EC parameters, checks for weak key sizes (≤512, ≤1024 bits), and searches certificate fields for flag patterns. |
| `padding_oracle.py` | `python3 padding_oracle.py --url URL --param PARAM --ciphertext HEX` | Automated CBC padding oracle attack. Decrypts ciphertext without the key by exploiting padding error responses. |
| `jwt_none.py` | `python3 jwt_none.py <token>` | Tests JWTs for the `alg:none` vulnerability. Strips the signature, forges arbitrary payload claims, and outputs the modified token. |
| `hash_identifier.py` | `python3 hash_identifier.py "<hash>"` | Identifies hash type by length, character set, and known prefixes (MD5, SHA-1/256/512, bcrypt, NTLM, etc.). |

### Forensics & File Analysis

| Script | Usage | What it does |
|--------|-------|-------------|
| `file_carver.py` | `python3 file_carver.py <binary>` | Carves embedded files out of binary blobs by scanning for magic bytes (ZIP, PNG, JPEG, ELF, PDF, GIF, WAV, MP3, 7z, RAR, and more). |
| `extract_all.py` | `python3 extract_all.py <file>` | Deep extractor — tries every known extraction method (binwalk-style) to find and unpack hidden files. |
| `strings_extractor.py` | `python3 strings_extractor.py <file> [--flags-only] [--offset]` | Pulls printable strings from any binary file with optional flag pattern search and byte offset reporting. |
| `entropy_scanner.py` | `python3 entropy_scanner.py <file> [-b BLOCKSIZE]` | Measures Shannon entropy block by block. High-entropy regions (>7.5 bits/byte) indicate encrypted or compressed hidden content. |
| `metadata_dumper.py` | `python3 metadata_dumper.py <file>` | Extracts EXIF data from images, PDF metadata, ZIP comments and extra fields, and PNG ancillary chunks. |
| `sql_inspector.py` | `python3 sql_inspector.py <database.db> [--blobs] [--search PATTERN]` | Dumps SQLite schema and all table contents, searches for flag patterns across every column, and extracts BLOB columns as binary files. |

### Network & PCAP

| Script | Usage | What it does |
|--------|-------|-------------|
| `pcap_extractor.py` | `python3 pcap_extractor.py <file.pcap> [--http] [--dns] [--search-flags]` | Reconstructs TCP/UDP streams from a capture file and extracts HTTP response bodies, DNS query names, and embedded files. Searches all stream data for flag patterns. |
| `dns_exfil_reader.py` | `python3 dns_exfil_reader.py <file.pcap> [-e hex\|base32\|base64url]` | Reassembles data exfiltrated over DNS by concatenating subdomain label chunks in sequence order. Supports hex, base32, and base64url encodings. |
| `wireshark_filter.py` | `python3 wireshark_filter.py "<description>"` | Converts natural language descriptions ("show me HTTP POST requests to 10.0.0.1") into Wireshark display filter syntax and equivalent `tshark` commands. |
| `routebuster.py` | `python3 routebuster.py <target>` | Network routing discovery for CTF network challenges. |

### Steganography

| Script | Usage | What it does |
|--------|-------|-------------|
| `lsb_extractor.py` | `python3 lsb_extractor.py <image.png> [--channel R\|G\|B\|A] [--bit 0-7]` | Extracts LSB-encoded hidden data from PNG/BMP pixel values across configurable channels and bit planes. |
| `wav_lsb.py` | `python3 wav_lsb.py <audio.wav> [--all] [-o output.bin]` | Extracts LSB steganographic data from WAV PCM samples. Tries all channel and bit-plane combinations with `--all`. |

### Binary / Reverse Engineering

| Script | Usage | What it does |
|--------|-------|-------------|
| `rust_demangler.py` | `python3 rust_demangler.py <binary> [--symbols]` | Rust binary analysis: detects Rust binaries, demangles symbols (uses `rustfilt` if available), extracts panic messages with source file paths, finds interesting functions (check/verify/decrypt), detects UPX packing. |
| `decompile_jar.py` | `python3 decompile_jar.py <file.jar>` | Decompiles JAR files to Java source using CFR. |
| `pyc_src_decompiler.py` | `python3 pyc_src_decompiler.py <file.pyc>` | Decompiles Python `.pyc` bytecode files back to readable source code. |

### Web & Node.js

| Script | Usage | What it does |
|--------|-------|-------------|
| `node_secrets_audit.py` | `python3 node_secrets_audit.py <directory> [--deep]` | Scans a Node.js/JavaScript project for hardcoded secrets, API keys, AWS credentials, JWTs, dangerous `eval`/`exec` calls, prototype pollution patterns, suspicious npm scripts, and non-standard package registries. `--deep` includes `node_modules`. |

---

## Requirements

Core scripts use only the Python standard library. The table below lists optional packages that unlock additional features — the scripts work without them but with reduced capability.

| Package | Install | Used by |
|---------|---------|---------|
| `Pillow` | `pip install Pillow` | `lsb_extractor.py` |
| `scapy` | `pip install scapy` | `pcap_extractor.py` |
| `pycryptodome` | `pip install pycryptodome` | `padding_oracle.py` |
| `gmpy2` | `pip install gmpy2` | `rsa_attack.py` (speeds up large integer ops) |
| `pyinstaller` | `pip install pyinstaller` | `build.sh` / `build.ps1` |
| `openssl` (CLI) | system package | `cert_inspector.py` |
| `rustfilt` (CLI) | `cargo install rustfilt` | `rust_demangler.py` (better demangling) |

The installer scripts (`install.sh` / `install.ps1`) handle all pip dependencies automatically.

---

## License

See [LICENSE](LICENSE).
