# Bruteforce XOR - CTFlearn
#Original challenge had the text q{vpln'bH_varHuebcrqxetrHOXEj

cipher = bytes("input", "utf-8")

for key in range(256):
    out = bytes([b ^ key for b in cipher])
    if all(32 <= c < 127 for c in out):  # printable
        print(key, out)
