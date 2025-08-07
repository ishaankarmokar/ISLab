message = "I am learning information security"
lex = ["a","b","c","d","e","f","g","h","i","j","k","l",
       "m","n","o","p","q","r","s","t","u","v","w","x","y","z"]

def additiveCipher(message, key, decipher = False):
    message = message.replace(" ", "")
    if not message.isalpha():
        return print("use alphabets only")
    message = message.lower()
    if decipher == False:
        ciphertext = ""
        for letter in message:
            c = (lex.index(letter) + key) % 26
            ciphertext += lex[c]
        return ciphertext
    if decipher == True:
        plaintext = ""
        for letter in message:
            p = (lex.index(letter) - key) % 26
            plaintext += lex[p]
        return plaintext

def findInverse(key):
    found = False
    x = 1
    while not found:
        if (key * x)%26 == 1:
            found = True
            return x
        x += 1

def multiplicativeCipher(message, key, decipher = False):
    if key not in [1,3,5,7,9,11,15,17,19,21,23,25]:
        return print("Invalid key")
    message = message.replace(" ", "")
    if not message.isalpha():
        return print("use alphabets only")
    message = message.lower()
    if decipher == False:
        ciphertext = ""
        for letter in message:
            c = (lex.index(letter) * key) % 26
            ciphertext += lex[c]
        return ciphertext
    if decipher == True:
        plaintext = ""
        for letter in message:
            p = (lex.index(letter) * findInverse(key)) % 26
            plaintext += lex[p]
        return plaintext

def affineCipher(message, key1, key2, decipher = False):
    if key1 not in [1,3,5,7,9,11,15,17,19,21,23,25]:
        return print("Invalid key1")
    message = message.replace(" ", "")
    if not message.isalpha():
        return print("use alphabets only")
    message = message.lower()
    if decipher == False:
        intermediate = multiplicativeCipher(message, key1)
        ciphertext = additiveCipher(intermediate, key2)
        return ciphertext
    if decipher == True:
        intermediate = additiveCipher(message, key2, True)
        plaintext = multiplicativeCipher(intermediate, key1, True)
        return plaintext


#Main Body
print("Original message: ", message)
print(" ")
ciphertext = additiveCipher(message, 20)
print("Enciphered by Additive Cipher:", ciphertext)
plaintext = additiveCipher(ciphertext, 20, True)
print("Deciphered by Additive Cipher:", plaintext)
print(" ")
ciphertext = multiplicativeCipher(message, 25)
print("Enciphered by Multiplicative Cipher:", ciphertext)
plaintext = multiplicativeCipher(ciphertext, 25, True)
print("Deciphered by Multiplicative Cipher:", plaintext)
print(" ")
ciphertext = affineCipher(message, 15, 20)
print("Enciphered by Affine Cipher:", ciphertext)
plaintext = affineCipher(ciphertext, 15, 20, True)
print("Deciphered by Affine Cipher:", plaintext)