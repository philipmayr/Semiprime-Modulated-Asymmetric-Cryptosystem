'''
This program implements an unpadded 32-bit RSA cryptosystem.

'''

import math, secrets

from primes import primes

def generate_prime(bit_length=16):
    while True:
        random_bits = secrets.randbits(bit_length)
        
        # turn on leading and trailing bits of mask to make sure prime candidate is both significantly large and odd
        bit_mask = (1 << (bit_length - 1)) | 1
        random_bits |= bit_mask
        
        if test_primality(random_bits):
            return random_bits


def generate_strong_prime_pair(difference_threshold=256):
    # generate string prime pair p, q of difference greater than 2^16
    while True:
        p = generate_prime()

        if test_twin_primality(p):
            continue
        
        q = generate_prime()

        if test_twin_primality(q):
            continue

        difference = p - q

        if difference < 0:
            difference = -difference

        if difference > difference_threshold:
            return p, q
            
            
def find_greatest_common_divisor(a, b):
    if b == 0:
        return a
    else:
        return find_greatest_common_divisor(b, a % b)
        
        
def test_coprimality(a, b):
    return find_greatest_common_divisor(a, b) == 1

    
def test_primality(prime_candidate):
    if (prime_candidate < 2):
        return False
        
    if (prime_candidate in (2, 3)):
        return True
    
    if (~prime_candidate & 1):
        return False

    for prime in primes:
        if (prime_candidate % prime) == 0:
            return False

    # n - 1 = 2ᵏ ⋅ m
    # n: prime candidate
    # k: index
    # m: multiplier
    
    multiplier = prime_candidate - 1
    binary_index = 0
    
    while (multiplier & 1) == 0:
        multiplier >>= 1
        binary_index += 1
            
    # 1 < a < n - 1
    # a: witness
    
    upper_bound = int(2 * (math.log(prime_candidate) ** 2))
    upper_bound = max(2, min(upper_bound, prime_candidate - 2))
    
    for witness in range(2, upper_bound + 1):
        
        # b₀ = aᵐ mod n
        # b = residue
        
        residue = exponentiate_modularly(witness, multiplier, prime_candidate)
        
        if residue == 1 or residue == prime_candidate - 1:
            continue
        
        for _ in range(binary_index - 1):
            residue = (residue * residue) % prime_candidate
            if residue == prime_candidate - 1:
                break
        else:
            return False
            
    return True


def test_twin_primality(twin_prime_candidate, primality=True):
    if primality:
        return test_primality(twin_prime_candidate + 2) or test_primality(twin_prime_candidate - 2)
    else:
        return test_primality(twin_prime_candidate) and test_primality(twin_prime_candidate + 2) or test_primality(twin_prime_candidate - 2)

    
def find_modular_multiplicative_inverse(base, modulus):
    if find_greatest_common_divisor(base, modulus) != 1:
        return None
    else:
        invertible_base = base
        
    if test_primality(modulus):
        phi_of_prime_modulus = modulus - 1
        modular_multiplicative_inverse = exponentiate_modularly(invertible_base, phi_of_prime_modulus - 1, modulus)
        
        return modular_multiplicative_inverse
    
    k = 0
    equation = lambda k : (1 + (k * modulus)) / (invertible_base)
    modular_multiplicative_inverse = equation(k)
    
    while (modular_multiplicative_inverse % 1 != 0):
        modular_multiplicative_inverse = equation(k)
        k += 1
        
    return int(modular_multiplicative_inverse)
    
    
def exponentiate(base, index):
    if base == 0:
        return 0
    if index == 0:
        return 1
    
    power = 1
    
    while (index):
        if index & 1:
            power *= base
            
        base *= base
        index >>= 1
            
    return power
    
    
def exponentiate_modularly(base, index, modulus):
    base %= modulus
    
    if base == 0:
        return 0
    if index == 0:
        return 1
        
    residue = 1
    
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
    private_encryption_exponent, modulus, private_encryption_exponent_modulo_phi_of_p, private_encryption_exponent_modulo_phi_of_q, p, q, modular_multiplicative_inverse_of_q_modulo_p = private_key
    
    # Optimization with Chinese Remainder Theorem (CRT)
    first_message = exponentiate_modularly(cipher, private_encryption_exponent_modulo_phi_of_p, p)
    second_message = exponentiate_modularly(cipher, private_encryption_exponent_modulo_phi_of_q, q)
    
    h = int((modular_multiplicative_inverse_of_q_modulo_p * (first_message - second_message))) % p
    
    message = second_message + (h * q)
    
    # message = exponentiate_modularly(cipher, private_encryption_exponent, modulus)
    
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
        print("Generating prime pair...")
        print()
        
        prime_pair_difference_threshold = 256

        p, q = generate_strong_prime_pair(prime_pair_difference_threshold)
        
        # public modulus (n)
        modulus = p * q
        
        # Euler's totient function φ(n) gives the count of numbers coprime to n,
        # that is, the count of numbers sharing no factor but 1 with n.
        # For every prime n, the count of numbers coprime to n is always n - 1,
        # since every number less than a prime n shares no factor but 1 with n.
        phi_of_p = p - 1
        phi_of_q = q - 1
        
        # Euler's totient function φ(n) holds the multiplicative property:
        # if a and b are coprime, then ϕ(a ⋅ b) = ϕ(a) ⋅ ϕ(b).
        phi_of_modulus = phi_of_p * phi_of_q
        
        # public decryption exponent (e)
        # e æ 65537 æ 2¹⁶ + 1 æ 10000000000000001
        public_decryption_exponent = 65537
        
        # e must be coprime to φ(modulus)
        if test_coprimality(public_decryption_exponent, phi_of_modulus) == False:
            raise ValueError("e is not coprime to φ(modulus).")
            
        # private encryption exponent (d)
        private_encryption_exponent = find_modular_multiplicative_inverse(public_decryption_exponent, phi_of_modulus)
        
        private_encryption_exponent_modulo_phi_of_p = private_encryption_exponent % phi_of_p
        private_encryption_exponent_modulo_phi_of_q = private_encryption_exponent % phi_of_q
        
        modular_multiplicative_inverse_of_q_modulo_p = find_modular_multiplicative_inverse(q, p)
        
        public_key = [public_decryption_exponent, modulus]
        private_key = [private_encryption_exponent, modulus, private_encryption_exponent_modulo_phi_of_p, private_encryption_exponent_modulo_phi_of_q, p, q, modular_multiplicative_inverse_of_q_modulo_p]
        
        # message must be greater than or equal to zero and less than modulus
        # message = int(input("Enter integer message → "))
        # if message < 0 or message >= modulus:
        #     raise ValueError("Message must be an integer not greater than or equal to zero and less than modulus.")
            
        # print()
        
        # cipher = encipher(message, public_key)
        # message = decipher(cipher, private_key)
        
        # print("Enciphered message → " + str(cipher))
        # print("Deciphered message → " + str(message))
        
        # print()
        
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
