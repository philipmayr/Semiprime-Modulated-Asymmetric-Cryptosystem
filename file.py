'''
This program is an implementation of the RSA encryption algorithm.

'''

def exponentiate(base, index):
    power = base
    
    while(index > 1):
        power *= base
        index -= 1
        
    return power


def encipher(plain_text, public_key):
    public_exponent, modulus = public_key
    
    cipher_text = exponentiate(plain_text, public_exponent) % modulus
    
    return cipher_text
    
    
def decipher(cipher_text, private_key):
    private_exponent, modulus = private_key
    
    plain_text = exponentiate(cipher_text, private_exponent) % modulus
    
    return plain_text


def encode(plain_text):
    encoded_text = []

    while(len(plain_text) > 0):
        character = plain_text[-1]
        encoded_character = ord(character)
        encoded_text.append(str(encoded_character))
        plain_text = plain_text[:-1]
        
    return encoded_text


def decode(encoded_text):
    decoded_text = []
    
    while(len(encoded_text) > 0):
        character = chr(int(encoded_text[-1]))
        decoded_text.append(character)
        encoded_text.pop(-1)
        
    return decoded_text


def main():
    # two unlike prime numbers
    p = 7
    q = 19
    
    modulus = p * q
    
    # φ(modulus)
    phi_of_modulus = (p - 1) * (q - 1)
    
    public_exponent = 5
    private_exponent = 2873
    
    public_key = [public_exponent, modulus]
    private_key = [private_exponent, modulus]
    
    plain_text = 37
    
    enciphered_text = encipher(plain_text, public_key)
    deciphered_text = decipher(enciphered_text, private_key)
    
    print(plain_text)
    print(enciphered_text)
    print(deciphered_text)
    
    message = "In the beginning, God created the heavens and the earth."
    
    encoded_text = encode(message)
    print(''.join(encoded_text))
    decoded_text = decode(encoded_text)
    print(''.join(decoded_text))


main()
