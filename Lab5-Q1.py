def djb2_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = (hash_value * 33) + ord(char)
    return hash_value & 0xFFFFFFFF

my_string = "Hello, World!"
hashed_value = djb2_hash(my_string)
print(f"The hash of '{my_string}' is: {hashed_value}")

'''The hash of 'Hello, World!' is: 2531426958'''