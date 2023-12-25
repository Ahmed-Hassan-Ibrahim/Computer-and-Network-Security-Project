import hashlib

def calculate_hash(file_path, hash_algorithm='sha256'):

    # Choose the hash algorithm
    if hash_algorithm not in hashlib.algorithms_available:
        raise ValueError(f"Invalid hash algorithm: {hash_algorithm}")

    # Open the input file in binary mode and read chunks for efficient memory usage
    hasher = hashlib.new(hash_algorithm)
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hasher.update(chunk)

    # Write the hexadecimal representation of the hash to the output file
    with open("Hash_Output", 'w') as output_file:
        output_file.write(hasher.hexdigest())

