'''
This program is an implementation of the RSA encryption algorithm.

'''


def find_greatest_common_divisor(a, b):
    if b == 0:
        return a
    else:
        return find_greatest_common_divisor(b, a % b)


def check_coprimality(a, b):
    return find_greatest_common_divisor(a, b) == 1


def find_modular_multiplicative_inverse_of_public_exponent(phi_of_modulus, public_exponent):
    k = 0
    equation = lambda k : (1 + (k * phi_of_modulus)) / (public_exponent)
    modular_multiplicative_inverse = equation(k)

    while(modular_multiplicative_inverse % 1 != 0):
        modular_multiplicative_inverse = equation(k)
        k += 1
        
    return modular_multiplicative_inverse
    

def exponentiate(base, index):
    power = base
    
    while(index > 1):
        power *= base
        index -= 1
        
    return power


def encipher(message, public_key):
    public_exponent, modulus = public_key
    
    cipher = exponentiate(message, public_exponent) % modulus
    
    return cipher
    
    
def decipher(cipher, private_key):
    private_exponent, modulus = private_key
    
    message = exponentiate(cipher, private_exponent) % modulus
    
    return message


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
    # unlike prime numbers p, q
    p = 7
    q = 19

    # n
    modulus = p * q
    
    # φ(modulus) (φ(n))
    phi_of_modulus = (p - 1) * (q - 1)

    # public/decryption exponent (e)
    # e = 2¹⁶ + 1 = 65537
    public_exponent = 65537
    
    # e must be coprime to φ(modulus)
    if check_coprimality(public_exponent, phi_of_modulus) == False:
        raise ValueError("e is not coprime to φ(modulus).")
        
    # private/encryption exponent (d)
    private_exponent = find_modular_multiplicative_inverse_of_public_exponent(phi_of_modulus, public_exponent)
    
    public_key = [public_exponent, modulus]
    private_key = [private_exponent, modulus]

    # message must be greater than or equal to zero and less than modulus
    message = 37
    if message < 0 or message >= modulus:
        raise ValueError("Message is not greater than or equal to zero and less than modulus.")
    
    cipher = encipher(message, public_key)
    message = decipher(cipher, private_key)
    
    print(message)
    print(cipher)
    print(message)
    
    message = "In the beginning, God created the heavens and the earth."
    
    encoded_text = encode(message)
    print(''.join(encoded_text))
    decoded_text = decode(encoded_text)
    print(''.join(decoded_text))


main()
