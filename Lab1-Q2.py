def generateKey(message, key):
    k = ""
    j = 0
    for i in range(len(message)):
        k += key[j]
        j = (j+1)%len(key)
    return k
def vigenereCipher(message, key, decipher = False):
    message = message.replace(" ", "")
    key = key.replace(" ", "")
    if not (message.isalpha() and key.isalpha()):
        return print("use alphabets only")
    message = message.lower()
    key = key.lower()
    key = generateKey(message,key)
    if decipher == False:
        ciphertext = ""
        for i in range(len(message)):
            letter = message[i]
            c = chr((ord(letter) + ord(key[i]) - 2*ord('a')) % 26 + ord('a'))
            ciphertext += c
        return ciphertext.upper()
    if decipher == True:
        plaintext = ""
        for i in range(len(message)):
            letter = message[i]
            p = chr((ord(letter) - ord(key[i]) + 26) % 26 + ord('a'))
            plaintext += p
        return plaintext

def autokeyCipher(message, key, decipher = False):
    autokey = chr(65 + key).lower()
    message = message.replace(" ", "")
    message = message.lower()

    if decipher == False:
        key = autokey + message
        ciphertext = ""
        for i in range(len(message)):
            letter = chr((ord(message[i]) + ord(key[i]) - 2*ord('a')) % 26 + ord('a'))
            ciphertext += letter
        return ciphertext.upper()
    if decipher == True:
        key = autokey
        plaintext = ""
        for i in range(len(message)):
            letter = message[i]
            p = chr((ord(letter) - ord(key[i]) + 26) % 26 + ord('a'))
            plaintext += p
            key += p
        return plaintext

#Main Body
message = "the house is being sold tonight"
print("Original message: ", message)
print(" ")
ciphertext = vigenereCipher(message, "dollars")
print("Enciphered by Vigenere Cipher:", ciphertext)
plaintext = vigenereCipher(ciphertext, "dollars", True)
print("Deciphered by Vigenere Cipher:", plaintext)
print(" ")
ciphertext = autokeyCipher(message, 7)
print("Enciphered by Autokey Cipher:", ciphertext)
plaintext = autokeyCipher(ciphertext, 7, True)
print("Deciphered by Autokey Cipher:", plaintext)
print(" ")