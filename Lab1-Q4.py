import numpy as np

def modInverse(a):
    for x in range(1, 26):
        if (a * x) % 26 == 1:
            return x
    return None

def hillCipher(message, key, decipher = False):
    message = message.replace(" ", "")
    message = message.upper()
    if len(message) % 2 != 0:
        message += 'X'
    if decipher == False:
        ciphertext = ""
        for i in range(0, len(message), 2):
            pvector = np.array([ord(message[i])-ord('A'),ord(message[i+1])-ord('A')])
            cvector = np.dot(key,pvector)%26
            ciphertext += chr(cvector[0] + ord('A'))+chr(cvector[1] + ord('A'))
        return ciphertext
    else:
        plaintext = ""
        det = np.linalg.det(key) % 26
        det_inv = modInverse(det)
        adj_key = np.array([
            [key[1, 1], -key[0, 1]],
            [-key[1, 0], key[0, 0]]
        ])
        inv_key = (adj_key * det_inv) % 26
        for i in range(0, len(message), 2):
            cvector = np.array([ord(message[i]) - ord('A'), ord(message[i + 1]) - ord('A')])
            pvector = np.dot(inv_key, cvector) % 26
            plaintext += chr(pvector[0] + ord('A')) + chr(pvector[1] + ord('A'))
        return plaintext.lower().replace("x", "")



#main body
key = np.array([[3,3],[2,7]])
message = "We live in an insecure world"
print("Original message: ", message)
print(" ")
ciphertext = hillCipher(message, key)
print("Enciphered by Hill Cipher:", ciphertext)
plaintext = hillCipher(ciphertext, key, True)
print("Deciphered by Hill Cipher:", plaintext)
