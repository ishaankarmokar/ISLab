import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from collections import defaultdict

SECRET_KEY = get_random_bytes(32)  # AES-256 Key
AES_BLOCK_SIZE = AES.block_size

DOCUMENTS = {
    1: "The quick brown fox jumps over the lazy dog.",
    2: "A fox is an omnivorous animal.",
    3: "The dog barks loudly at the cat."
}

def encrypt(key, data_list):
    """Encrypts a list of DocIDs."""
    data_bytes = json.dumps(data_list).encode('utf-8')
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes, AES_BLOCK_SIZE))
    return binascii.hexlify(iv + ciphertext).decode('utf-8')


def decrypt(key, iv_ciphertext_hex):
    """Decrypts a hex-encoded IV+Ciphertext back to a list of DocIDs."""
    iv_ciphertext = binascii.unhexlify(iv_ciphertext_hex)
    iv = iv_ciphertext[:AES_BLOCK_SIZE]
    ciphertext = iv_ciphertext[AES_BLOCK_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)
    return json.loads(decrypted_data.decode('utf-8'))



def build_encrypted_index(key, corpus):
    idx = defaultdict(list)
    # Build Plaintext Index
    for doc_id, content in corpus.items():
        words = set(content.lower().replace('.', '').split())
        for word in words:
            if doc_id not in idx[word]:
                idx[word].append(doc_id)

    # Encrypt Index Values (DocID lists)
    encrypted_idx = {
        word: encrypt(key, doc_id_list)
        for word, doc_id_list in idx.items()
    }
    return encrypted_idx


def search(key, encrypted_index, query):
    query_terms = set(query.lower().split())

    # Simulate Server Search: Retrieve Encrypted DocID lists
    encrypted_results = [
        encrypted_index[term] for term in query_terms
        if term in encrypted_index
    ]

    if not encrypted_results:
        return {}
    # Simulate Client Decryption and Intersection
    # Start with the decrypted list of the first term
    final_doc_id_set = set(decrypt(key, encrypted_results[0]))

    # Intersect with the remaining decrypted lists
    for result_hex in encrypted_results[1:]:
        decrypted_list = decrypt(key, result_hex)
        final_doc_id_set.intersection_update(decrypted_list)

    # Decrypt returned Document IDs and display the corresponding documents
    result_docs = {
        doc_id: DOCUMENTS[doc_id]
        for doc_id in final_doc_id_set
    }
    return result_docs


# --- Execution Example ---
if __name__ == "__main__":

    # 1c. Create Encrypted Index
    E_INDEX = build_encrypted_index(SECRET_KEY, DOCUMENTS)

    print("--- Basic SSE Demonstration ---")
    print(f"Secret Key (K): {binascii.hexlify(SECRET_KEY).decode('utf-8')[:8]}...")
    print(f"Encrypted Index Size: {len(E_INDEX)} terms.")
    print(f"Encrypted Entry Example: 'fox' -> {E_INDEX['fox'][:30]}...")

    # 1d. Implement Search
    SEARCH_QUERY = "quick dog"
    results = search(SECRET_KEY, E_INDEX, SEARCH_QUERY)

    print("\n--- Search Results ---")
    print(f"Query: '{SEARCH_QUERY}'")

    if results:
        for doc_id, content in results.items():
            print(f"Doc {doc_id}: {content}")
    else:
        print("No documents matched the query.")


'''
--- Basic SSE Demonstration ---
Secret Key (K): ea1361a5...
Encrypted Index Size: 17 terms.
Encrypted Entry Example: 'fox' -> ccfccc7e847de4814399a3c03f5c5c...

--- Search Results ---
Query: 'quick dog'
Doc 1: The quick brown fox jumps over the lazy dog.
'''