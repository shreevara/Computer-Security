import sys

def encrypt(plaintext, key):
    ciphertext = ''
    keylength = len(key)
    
    # Pad plaintext with 'z' if needed
    padding = keylength - (len(plaintext) % keylength)
    if padding != keylength:
        plaintext += 'z' * padding
    
    # Write plaintext in rows based on keylength
    rows = [plaintext[i:i+keylength] for i in range(0, len(plaintext), keylength)]
    
    # Rearrange columns based on key
    for i in key:
        ciphertext += ''.join([row[int(i)-1] for row in rows])
    
    return ciphertext

# Function to perform row transposition decryption
def decrypt(keylength, key, ciphertext):
    num_rows = len(ciphertext) // keylength
    num_columns = keylength
    plaintext = [''] * num_rows
    column_order = [int(k) - 1 for k in key]

    for col in range(num_columns):
        current_column = column_order.index(col)
        start = current_column * num_rows
        end = start + num_rows
        plaintext_row = ciphertext[start:end]
        plaintext = [p + c for p, c in zip(plaintext, plaintext_row)]

    return ''.join(plaintext)




if __name__ == '__main__':
    if len(sys.argv) != 6:
        print('Usage: python3 trans.py <keylength> <key> <inputfile> <outputfile> <enc/dec>')
        sys.exit(1)
        
    keylength = int(sys.argv[1])
    key = sys.argv[2]
    inputfile = sys.argv[3]
    outputfile = sys.argv[4]
    mode = sys.argv[5]
    
    if len(key) != keylength:
        print('Error: Key length does not match')
        sys.exit(1)
        
    unique_digits = set(key)
    if len(unique_digits) != keylength or not all(c.isdigit() for c in unique_digits):
        print('Error: Key must contain digits 1 to keylength')
        sys.exit(1) 
    
    with open(inputfile, 'r') as f:
        plaintext = f.read()
    if not all(c.islower() or c.isdigit() for c in plaintext):
        print('Error: Input file must contain only lower case letters or digits')
        sys.exit(1)
        
    if mode == 'enc':
        ciphertext = encrypt(plaintext, key)
    elif mode == 'dec':
        ciphertext = decrypt(keylength, key, plaintext)
    else:
        print('Error: Invalid mode')
        sys.exit(1)
    
    with open(outputfile, 'w') as f:
        f.write(ciphertext)