import platform
import time
import sys
import binascii
import marshal
import dis
import struct
import shutil

# Try importing uncompyle6
try:
    import uncompyle6
    HAS_UNCOMPYLE6 = True
except ImportError:
    HAS_UNCOMPYLE6 = False

# Try importing decompyle3
try:
    import decompyle3
    HAS_DECOMPYLE3 = True
except ImportError:
    HAS_DECOMPYLE3 = False


def get_python_version_from_magic(magic_int):
    # Partial mapping of magic numbers to Python versions
    magic_map = {
        20121: '1.5', 50428: '1.6', 50823: '2.0',
        60202: '2.1', 60717: '2.2', 62011: '2.3',
        62021: '2.4', 62131: '2.5', 62161: '2.6',
        62211: '2.7',
        3000: '3.0', 3150: '3.1', 3180: '3.2',
        3230: '3.3', 3310: '3.4', 3350: '3.5',
        3379: '3.6', 3394: '3.7', 3413: '3.8',
        3425: '3.9', 3439: '3.10', 3495: '3.11',
        3550: '3.12', 3571: '3.13'
    }
    # Values are approximate base magic numbers.
    # Python 3 uses ranges sometimes, but this is a best effort.
    for k, v in sorted(magic_map.items(), reverse=True):
        if magic_int >= k:
            return v
    return "Unknown"

def view_pyc_file(path):
    """Read and display content of the Python bytecode in a pyc-file."""

    print(f"Processing: {path}")
    print("=" * 60)

    try:
        with open(path, 'rb') as f:
            # 1. Parse Header
            magic = f.read(4)
            magic_int = int.from_bytes(magic[:2], 'little')
            
            print(f"Magic Number: {binascii.hexlify(magic).decode('utf-8')} (Decimal: {magic_int})")
            
            guessed_version = get_python_version_from_magic(magic_int)
            print(f"Likely Python Version: {guessed_version}")

            bit_field = None
            timestamp = None
            size = None
            
            # Logic to parse header based on version heuristics
            # Python 3.7+ (Magic >= 3390 approx) : 16 bytes: [Magic 4] [Bitfield 4] [Timestamp 4] [Size 4]
            # Python 3.3+ (Magic >= 3230)        : 12 bytes: [Magic 4] [Timestamp 4] [Size 4]
            # Python < 3.3                       : 8 bytes:  [Magic 4] [Timestamp 4]
            
            # Note: Python 2 magic numbers are large (e.g. 62211 for 2.7), so checking >= 3390 is not enough.
            # We must distinguish Py3 ranges from Py2 ranges.
            
            header_size = 8
            
            if 3390 <= magic_int < 4000: # 3.7+
                bit_field_bytes = f.read(4)
                bit_field = struct.unpack('I', bit_field_bytes)[0]
                timestamp_bytes = f.read(4)
                size_bytes = f.read(4)
                timestamp = struct.unpack('I', timestamp_bytes)[0]
                size = struct.unpack('I', size_bytes)[0]
                header_size = 16
            elif 3230 <= magic_int < 3390: # 3.3+
                timestamp_bytes = f.read(4)
                size_bytes = f.read(4)
                timestamp = struct.unpack('I', timestamp_bytes)[0]
                size = struct.unpack('I', size_bytes)[0]
                header_size = 12
            else: # < 3.3 or Py2
                 timestamp_bytes = f.read(4)
                 timestamp = struct.unpack('I', timestamp_bytes)[0]
                 header_size = 8

            if bit_field is not None:
                print(f"Bit Field:    {bit_field}")
            
            if timestamp is not None:
                try:
                     print(f"Timestamp:    {time.asctime(time.localtime(timestamp))} ({timestamp})")
                except:
                     print(f"Timestamp:    {timestamp} (Invalid/Hash based?)")
            
            if size is not None:
                print(f"Content Size: {size} bytes")

            print("-" * 60)

            # 2. Unmarshal Code
            code = None
            try:
                code = marshal.load(f)
                print("Code object loaded successfully.")
            except Exception as e:
                print(f"ERROR: Failed to unmarshal code object: {e}")
                print(f"Details: {sys.exc_info()[0].__name__}")
                if magic_int > 4000 and sys.version_info.major == 3:
                     print("Reason: You are likely trying to open a Python 2.x file with Python 3.x.")
                     print("        Python 3's 'marshal' module cannot load Python 2 bytecode.")

            # 3. Disassembly
            if code:
                print("\nBytecode Disassembly:")
                print("-" * 60)
                try:
                    dis.disassemble(code)
                except Exception as e:
                    print(f"Disassembly error: {e}")

            # 4. Decompilation
            print("\n" + "=" * 60)
            print("Decompiled Source Code:")
            print("-" * 60)
            
            decompiled = False
            
            # Attempt with uncompyle6
            if HAS_UNCOMPYLE6:
                try:
                    import io
                    output = io.StringIO()
                    # If we have a code object, use verify+decompile
                    # If we don't (marshal failed), try decompile_file direct
                    if code:
                        uncompyle6.main.decompile(None, code, output)
                    else:
                        print("Attempting to use uncompyle6 directly on file (ignoring marshal error)...")
                        # uncompyle6.decompile_file writes to stdout unless outstream provided?
                        # Checking signature... usually decompile_file(filename, outstream=...)
                        # Note: This might vary by version.
                        try:
                             uncompyle6.main.decompile_file(path, output)
                        except AttributeError:
                             # Fallback for some versions
                             from uncompyle6.bin import decompile_file
                             decompile_file(path, output)

                    print(output.getvalue())
                    decompiled = True
                except Exception as e:
                    print(f"uncompyle6 logic failed: {e}")

            # Attempt with decompyle3
            if not decompiled and HAS_DECOMPYLE3:
                 try:
                    import io
                    output = io.StringIO()
                    if code:
                         decompyle3.decompile(code, outstream=output)
                         decompiled = True
                         print(output.getvalue())
                 except Exception as e:
                     print(f"decompyle3 failed: {e}")
            
            if not decompiled:
                if not HAS_UNCOMPYLE6 and not HAS_DECOMPYLE3:
                    print("Decompilation tools not found.")
                    print("Install 'uncompyle6' to decompile Python 2.7 or 3.x bytecode:")
                    print("  pip install uncompyle6")
                elif not code:
                     print("Could not load code object and decompilers failed.")

    
    except IOError as e:
        print(f"Could not open file: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.pyc>")
    else:
        view_pyc_file(sys.argv[1])
