from phe import paillier


docs = [
    "The quick brown fox jumps over the lazy dog.",
    "A fox is an omnivorous animal.",
    "The dog barks loudly at the cat."
]


pub_key, priv_key = paillier.generate_paillier_keypair()

def encrypt_num(num):
    return pub_key.encrypt(num)

def decrypt_num(enc_num):
    return priv_key.decrypt(enc_num)


index = {}
for i, doc in enumerate(docs):
    for w in set(doc.split()):
        index.setdefault(w, []).append(i)

enc_index = {w: [encrypt_num(d) for d in ids] for w, ids in index.items()}


def search(query):
    q_enc = query.split()  # multiple words, no encryption needed here for searching keys
    results_enc = []
    for word in q_enc:
        if word in enc_index:
            results_enc.extend(enc_index[word])
    results_dec = [decrypt_num(doc_id) for doc_id in results_enc]
    return sorted(set(results_dec))

# Example usage
print("Search results for 'fox':", search("fox"))

'''
Search results for 'fox': [0, 1]

'''