import os
import random
import shutil

BASE_DIR = "crypto_mess"
TARGET_DIR = "massive_crypto_data"
TARGET_COUNT = 1000000  # Adjust as needed

# Copy base dataset with permutations
file_count = 0
for path, _, files in os.walk(BASE_DIR):
    for file in files:
        src = os.path.join(path, file)
        rel_path = os.path.relpath(src, BASE_DIR)
        
        # Create multiple variants
        for i in range(random.randint(3, 15)):
            if file_count >= TARGET_COUNT:
                break
                
            # Scramble directory structure
            new_path = os.path.join(TARGET_DIR, *rel_path.split(os.sep)[:-1], f"v{i}")
            os.makedirs(new_path, exist_ok=True)
            
            # Randomize filenames
            new_name = f"{os.urandom(4).hex()}{os.path.splitext(file)[1]}"
            dest = os.path.join(new_path, new_name)
            
            # Random content tweaks
            if random.random() < 0.3:  # 30% get modified
                with open(src, "rb") as f_src, open(dest, "wb") as f_dest:
                    data = f_src.read()
                    if random.random() < 0.5 and len(data) > 10:  # Introduce errors
                        pos = random.randint(0, len(data)-1)
                        data = data[:pos] + bytes([data[pos] ^ 0xFF]) + data[pos+1:]
                    f_dest.write(data)
            else:
                shutil.copy2(src, dest)
            
            file_count += 1

# Add noise files
NOISE_RATIO = 0.05  # 5% noise files
for _ in range(int(TARGET_COUNT * NOISE_RATIO)):
    dir_path = os.path.join(TARGET_DIR, *[f"dir_{i}" for i in range(random.randint(1, 5))])
    os.makedirs(dir_path, exist_ok=True)
    
    # Generate random content
    with open(os.path.join(dir_path, f"noise_{os.urandom(2).hex()}"), "wb") as f:
        if random.random() < 0.7:  # Text-like
            f.write(os.urandom(random.randint(100, 5000)))
        else:  # Binary
            f.write(b'\x00' * random.randint(10, 1000))
