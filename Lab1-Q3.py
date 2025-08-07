def createPlayfairMatrix(key):
    key = dict.fromkeys(key.upper().replace("J","I"))
    key = "".join(key)
    order = ""
    alphabet ="ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for i in key:
        order += i
    for i in alphabet:
        if i not in order:
            order += i
    matrix = []
    for i in range(0,25,5):
        sublist = list(order[i:i+5])
        matrix.append(sublist)
    return matrix

def processMessage(message):
    message = message.upper().replace("J","I").replace(" ", "")
    processedMessage = ""
    for i in range(len(message)):
        processedMessage += message[i]
        if i+1 < len(message) and message[i] == message[i+1]:
            processedMessage += "X"
    if len(processedMessage) % 2 != 0:
        processedMessage += "X"
    return processedMessage

def findCoords(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return (i, j)

def playfairCipher(message, key, decipher = False):
    matrix = createPlayfairMatrix(key)
    if decipher == False:
        message = processMessage(message)
        ciphertext = ""
        for i in range(0,len(message),2):
            a = findCoords(matrix,message[i])
            b = findCoords(matrix,message[i+1])
            if a[0] == b[0]:
                ciphertext += matrix[a[0]][(a[1] + 1) % 5]
                ciphertext += matrix[b[0]][(b[1] + 1) % 5]
            elif a[1] == b[1]:
                ciphertext += matrix[(a[0] + 1) % 5][a[1]]
                ciphertext += matrix[(b[0] + 1) % 5][b[1]]
            else:
                ciphertext += matrix[a[0]][b[1]]
                ciphertext += matrix[b[0]][a[1]]
        return ciphertext
    else:
        plaintext = ""
        for i in range(0,len(message),2):
            a = findCoords(matrix,message[i])
            b = findCoords(matrix,message[i+1])
            if a[0] == b[0]:
                plaintext += matrix[a[0]][(a[1] - 1 + 5) % 5]
                plaintext += matrix[b[0]][(b[1] - 1 + 5) % 5]
            elif a[1] == b[1]:
                plaintext += matrix[(a[0] - 1 + 5) % 5][a[1]]
                plaintext += matrix[(b[0] - 1 + 5) % 5][b[1]]
            else:
                plaintext += matrix[a[0]][b[1]]
                plaintext += matrix[b[0]][a[1]]
        return plaintext.lower().replace("x","")

# Main Body
message = "The key is hidden under the door pad"
key = "GUIDANCE"
print("Original message: ", message)
print("Secret key: ", key)
print(" ")
ciphertext = playfairCipher(message, key)
print("Enciphered by Playfair Cipher:", ciphertext)
plaintext = playfairCipher(ciphertext, key, decipher=True)
print("Deciphered by Playfair Cipher:", plaintext)