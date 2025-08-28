import hashlib
import random
import string
import time

def generate_random_strings(min_count=50, max_count=100, str_length=20):
    count = random.randint(min_count, max_count)
    dataset = []
    for _ in range(count):
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=str_length))
        dataset.append(s)
    return dataset

def compute_hashes(dataset, hash_func_name):
    hashes = {}
    start_time = time.time()
    for data in dataset:
        h = hashlib.new(hash_func_name)
        h.update(data.encode())
        hashes[data] = h.hexdigest()
    elapsed_time = time.time() - start_time
    return hashes, elapsed_time

def detect_collisions(hashes):
    reverse_map = {}
    for original, hash_val in hashes.items():
        reverse_map.setdefault(hash_val, []).append(original)
    collisions = [group for group in reverse_map.values() if len(group) > 1]
    return collisions

def experiment():
    dataset = generate_random_strings()
    print(f"Generated dataset with {len(dataset)} random strings.")

    for algo in ['md5', 'sha1', 'sha256']:
        hashes, elapsed = compute_hashes(dataset, algo)
        collisions = detect_collisions(hashes)
        print(f"\nAlgorithm: {algo.upper()}")
        print(f"Time taken to hash dataset: {elapsed:.6f} seconds")
        if collisions:
            print(f"Number of collisions detected: {len(collisions)}")
            for i, group in enumerate(collisions, 1):
                print(f"  Collision group {i}: {group}")
        else:
            print("No collisions detected.")

if __name__ == "__main__":
    experiment()

'''Generated dataset with 65 random strings.

Algorithm: MD5
Time taken to hash dataset: 0.000000 seconds
No collisions detected.

Algorithm: SHA1
Time taken to hash dataset: 0.002020 seconds
No collisions detected.

Algorithm: SHA256
Time taken to hash dataset: 0.000000 seconds
No collisions detected.
'''