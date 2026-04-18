# Given A/B string
ctf_string = "ABAAAABABAABBABBAABBAABAAAAAABAAAAAAAABAABBABABBAAAAABBABBABABBAABAABABABBAABBABBAABB"

# Split into groups of 5 letters
groups = [ctf_string[i:i+5] for i in range(0, len(ctf_string), 5)]
groups = [g for g in groups if len(g) == 5]  # Remove incomplete groups

# Function to convert A/B to letters using Bacon's cipher
def ab_to_letter(group):
    binary = ''.join(['0' if c=='A' else '1' for c in group])
    num = int(binary, 2)
    # Map 0-25 to A-Z (classic Bacon cipher)
    if num <= 25:
        return chr(ord('A') + num)
    else:
        return '?'

# Decode all groups
decoded = ''.join([ab_to_letter(g) for g in groups])
print("Decoded flag:", decoded)
