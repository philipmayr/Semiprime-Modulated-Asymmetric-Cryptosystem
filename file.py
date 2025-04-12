
'''
This program implements the RSA cryptosystem.

'''

import random


def generate_prime(bit_length=16):
    while True:
        random_bits = random.getrandbits(bit_length)
        
        # turn on leading and trailing bits of mask to make sure prime candidate is both significantly large and odd
        bit_mask = (1 << (bit_length - 1)) | 1
        random_bits |= bit_mask
        
        if test_primality(random_bits):
            return random_bits
            

def find_greatest_common_divisor(a, b):
    if b == 0:
        return a
    else:
        return find_greatest_common_divisor(b, a % b)


def test_coprimality(a, b):
    return find_greatest_common_divisor(a, b) == 1
    
    
def test_primality(prime_candidate):
    '''
    
    TODO: 
    
    1. divide prime candidate by first few hundred pre-generated primes:
       return false if prime candidate divides evenly
       
    2. test prime candidate for perfect exponentiality:
       return false if prime candidate is a perfect power
       
    '''
        
    # n - 1 = 2ᵏ ⋅ m
    # n: prime candidate
    # k: index
    # m: quotient
    
    index = 1
    
    while True:
        if prime_candidate - 1 % exponentiate(2, index) == 0:
            index += 1
        else:
            index -= 1
            break
        
    quotient = (prime_candidate - 1) / exponentiate(2, index)
        
    # 1 < a < n - 1
    # a: witness
    
    witness = random.randint(2, prime_candidate - 2)
    
    # b₀ = aᵐ mod n
    # b = residue
    
    residue = exponentiate_modularly(witness, quotient, prime_candidate)
    
    if residue == 1 or residue == -1 or residue == (residue - prime_candidate):
        return True
    else:
        residue = exponentiate_modularly(residue, 2, prime_candidate)
        if residue == 1:
            return False
        elif residue == -1 or (residue - prime_candidate == -1):
            return True
    
    return False
        

def find_modular_multiplicative_inverse_of_public_decryption_exponent_with_respect_to_phi_of_modulus(phi_of_modulus, public_decryption_exponent):
    k = 0
    equation = lambda k : (1 + (k * phi_of_modulus)) / (public_decryption_exponent)
    modular_multiplicative_inverse = equation(k)

    while (modular_multiplicative_inverse % 1 != 0):
        modular_multiplicative_inverse = equation(k)
        k += 1
        
    return modular_multiplicative_inverse
    

def exponentiate(base, index):
    if index == 0:
        return 1
    elif index == 1:
        return base
    else:
        power = base
        
        while (index > 1):
            power *= base
            index -= 1
            
    return power
        
        
def exponentiate_modularly(base, index, modulus):
    if index == 0:
        return 1
    elif index == 1:
        return base
        
    residue = 1
    
    base %= modulus
    
    if base == 0:
        return 0
        
    index = int(index)
        
    while index > 0:
        if index & 1:
            residue = (residue * base) % modulus
            
        base = (base * base) % modulus
        index >>= 1
        
    return residue


def encipher(message, public_key):
    public_decryption_exponent, modulus = public_key
    
    cipher = exponentiate_modularly(message, public_decryption_exponent, modulus)
    
    return cipher
    
    
def decipher(cipher, private_key):
    private_encryption_exponent, modulus = private_key
    
    message = exponentiate_modularly(cipher, private_encryption_exponent, modulus)
    
    return message


def encode(plain_text):
    encoded_text = []

    while (len(plain_text) > 0):
        character = plain_text[-1]
        encoded_character = ord(character)
        encoded_text.append(str(encoded_character))
        plain_text = plain_text[:-1]
        
    return encoded_text


def decode(encoded_text):
    decoded_text = []
    
    while (len(encoded_text) > 0):
        character = chr(int(encoded_text[-1]))
        decoded_text.append(character)
        encoded_text.pop(-1)
        
    return decoded_text
    
    
def encrypt(plain_text, public_key):
    cipher_text = []    

    initial_length = len(plain_text)
    current_length = initial_length
    
    while (current_length > 0):
        message = int(plain_text[-1])
        cipher = encipher(message, public_key)
        cipher_text.append(str(cipher))
        print_progress(initial_length - current_length, initial_length)
        plain_text.pop(-1)
        current_length = len(plain_text)
        
    print_progress(initial_length, initial_length)

    return cipher_text
        

def decrypt(cipher_text, private_key):
    plain_text = []
    
    while (len(cipher_text) > 0):
        cipher = int(cipher_text[-1])
        plain_text.append(str(decipher(cipher, private_key)))
        cipher_text.pop(-1)
        
    return plain_text


def print_progress(current, total):
    fraction = (current / total)
    percentage = int(fraction * 100)
    
    status_message = "Encrypting message... " + str(percentage) + "% complete."

    if current == total:
        print('\r' + status_message, end='\n\n')
    else:
        print(status_message, end='\r')
        

def main():
    while (True):
        print("Generating primes...")
        print()
        
        # generate pair of unlike prime numbers (p, q)
        p = generate_prime()
        q = generate_prime()
    
        # n
        modulus = p * q

        # φ(p)
        phi_of_p = p - 1
        # φ(q)
        phi_of_q = q - 1
        
        # φ(modulus) (φ(n))
        phi_of_modulus = phi_of_p * phi_of_q
    
        # set public decryption exponent (e)
        # e = 2¹⁶ + 1 = 65537
        # e = 10000000000000001
        public_decryption_exponent = 65537
        
        # e must be coprime to φ(modulus)
        if test_coprimality(public_decryption_exponent, phi_of_modulus) == False:
            raise ValueError("e is not coprime to φ(modulus).")
            
        # set private encryption exponent (d)
        private_encryption_exponent = find_modular_multiplicative_inverse_of_public_decryption_exponent_with_respect_to_phi_of_modulus(phi_of_modulus, public_decryption_exponent)
        
        public_key = [public_decryption_exponent, modulus]
        private_key = [private_encryption_exponent, modulus]
    
        # message must be greater than or equal to zero and less than modulus
        message = int(input("Enter integer message → "))
        if message < 0 or message >= modulus:
            raise ValueError("Message must be an integer not greater than or equal to zero and less than modulus.")
            
        print()
        
        cipher = encipher(message, public_key)
        message = decipher(cipher, private_key)
        
        print("Enciphered message → " + str(cipher))
        print("Deciphered message → " + str(message))
        
        print()
        
        # message = "«בראשית ברא אלהים את השמים ואת הארץ»"
        message = input("Enter text message → ")
    
        print()
        
        encoded_text = encode(message)
        print("Encoded message → " + ''.join(encoded_text))
        
        print()
        
        encrypted_text = encrypt(encoded_text, public_key)
        print("Encrypted message → " + ''.join(encrypted_text))
        
        print()
        
        decrypted_text = decrypt(encrypted_text, private_key)
        print("Decrypted message → " + ''.join(decrypted_text))
        
        print()
        
        decoded_text = decode(decrypted_text)
        print("Decoded message → " + ''.join(decoded_text))
    
        print("\n◇◇◇\n")


main()
