import os
import hashlib

# Root directory of your project
base_dir = "C:\\Users\\hp\\Desktop\\OS-PBL"

# Function to compute hash
def compute_sha256(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

# Collect and print hashes for all .py files
trusted_hashes = {}
for root, dirs, files in os.walk(base_dir):
    for file in files:
        if file.endswith(".py"):
            full_path = os.path.join(root, file)
            hash_val = compute_sha256(full_path)
            trusted_hashes[file] = hash_val

# Print trusted_hashes dictionary
print("trusted_hashes = {")
for filename, hash_val in trusted_hashes.items():
    print(f"    '{filename}': '{hash_val}',")
print("}")
