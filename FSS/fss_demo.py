import hashlib
import random

# Key generation
def generate_keys(bit_length=512):
    # Choose two large primes p and q (for demo, small values used)
    p = 499
    q = 547
    n = p * q
    s = random.randint(2, n - 1)
    while gcd(s, n) != 1:
        s = random.randint(2, n - 1)
    v = pow(s, 2, n)
    return {'n': n, 'v': v, 's': s}

# GCD function
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Fiat-Shamir hash challenge
def fiat_shamir_challenge(x, n):
    h = hashlib.sha256()
    h.update(str(x).encode() + str(n).encode())
    digest = h.digest()
    # Use least significant bit as challenge bit (0 or 1)
    return digest[-1] & 1

# Prover creates proof
def create_proof(secret, public_n, public_v):
    r = random.randint(1, public_n - 1)
    x = pow(r, 2, public_n)
    e = fiat_shamir_challenge(x, public_n)
    if e == 0:
        y = r
    else:
        y = (r * secret) % public_n
    return {'x': x, 'y': y, 'e': e}

# Verifier checks proof
def verify_proof(proof, public_n, public_v):
    x, y, e = proof['x'], proof['y'], proof['e']
    lhs = pow(y, 2, public_n)
    if e == 0:
        rhs = x % public_n
    else:
        rhs = (x * public_v) % public_n
    return lhs == rhs

# Example usage
keys = generate_keys()
proof = create_proof(keys['s'], keys['n'], keys['v'])
valid = verify_proof(proof, keys['n'], keys['v'])

print(f"Public Key (n, v): ({keys['n']}, {keys['v']})")
print(f"Proof (x, y, e): ({proof['x']}, {proof['y']}, {proof['e']})")
print(f"Verification result: {'Valid' if valid else 'Invalid'}")
