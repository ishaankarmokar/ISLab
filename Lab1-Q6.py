message = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
lex = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
       "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]


def findInverse(key):
    x = 1
    while True:
        if (key * x) % 26 == 1:
            return x
        x += 1


def additiveCipher(message, key, decipher=False):
    message = message.replace(" ", "")
    if not message.isalpha():
        return "use alphabets only"
    message = message.lower()
    result = ""
    for letter in message:
        if decipher:
            c = (lex.index(letter) - key) % 26
        else:
            c = (lex.index(letter) + key) % 26
        result += lex[c]
    return result


def multiplicativeCipher(message, key, decipher=False):
    if key not in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
        return "Invalid key"
    message = message.replace(" ", "")
    if not message.isalpha():
        return "use alphabets only"
    message = message.lower()
    result = ""
    if decipher:
        inverse_key = findInverse(key)
        for letter in message:
            p = (lex.index(letter) * inverse_key) % 26
            result += lex[p]
    else:
        for letter in message:
            c = (lex.index(letter) * key) % 26
            result += lex[c]
    return result


def affineCipher(message, key1, key2, decipher=False):
    if key1 not in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
        return "Invalid key1"
    message = message.replace(" ", "")
    if not message.isalpha():
        return "use alphabets only"
    message = message.lower()
    if decipher:
        intermediate = additiveCipher(message, key2, True)
        plaintext = multiplicativeCipher(intermediate, key1, True)
        return plaintext
    else:
        intermediate = multiplicativeCipher(message, key1)
        ciphertext = additiveCipher(intermediate, key2)
        return ciphertext


def affineBruteForce(ciphertext, plaintext_pair):
    known_p1, known_p2 = plaintext_pair[0], plaintext_pair[1]
    known_c1, known_c2 = "g", "l"

    a_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    b_values = range(26)

    for a in a_values:
        for b in b_values:
            p1_index = lex.index(known_p1)
            c1_index = lex.index(known_c1)

            p2_index = lex.index(known_p2)
            c2_index = lex.index(known_c2)

            if (a * p1_index + b) % 26 == c1_index:

                if (a * p2_index + b) % 26 == c2_index:
                    print(f"Key found! (a={a}, b={b})")
                    return affineCipher(ciphertext, a, b, True)
    return "Key not found."


print("Original message: ", message)
print(" ")
plaintext_message = affineBruteForce(message, "ab")
print("Deciphered by Brute Force Attack:", plaintext_message)