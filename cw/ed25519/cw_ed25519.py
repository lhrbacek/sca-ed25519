from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Hash import SHAKE256
from Crypto.Signature import eddsa

#from curve25519 import _raw_curve25519

class Ed25519:
    p: int = 2 ** 255 - 19
    p_bytes: bytes = bytes.fromhex('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed')
    a_bytes: bytes = bytes.fromhex('7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec')
    d_bytes: bytes = bytes.fromhex('52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3')
    G: ECC.EccPoint = ECC.EccPoint(int.from_bytes(bytes.fromhex('216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A'), byteorder="big"),
                                   int.from_bytes(bytes.fromhex('6666666666666666666666666666666666666666666666666666666666666658'), byteorder="big"),
                                   curve='Ed25519')
    G_ma_u: int = 9
    G_ma_v: int = 14781619447589544791020593568409986887264606134616475288964881837755586237401
    L_bytes: bytes = bytes.fromhex('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed')


# Taken and modified from RFC 8032
def point_compress(P: ECC.EccPoint, p: int):
    return int.to_bytes((int(P.y) % p) | (((int(P.x) % p) & 1) << 255), length=32, byteorder='little')


# Taken and modified from RFC 8032
def modp_inv(x):
    return pow(x, Ed25519.p - 2, Ed25519.p) # x^(p-2) % p


# Square root of -1 from RFC 8032
modp_sqrt_m1 = pow(2, (Ed25519.p - 1) // 4, Ed25519.p)


# Compute corresponding x-coordinate, with low bit corresponding to sign, or return None on failure
# Taken and modified from RFC 8032
def recover_x(y, sign):
    p = Ed25519.p
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(int.from_bytes(Ed25519.d_bytes, byteorder='big')*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)

    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p

    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x


# Taken and modified from RFC 8032
def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return ECC.EccPoint(x, y, curve='Ed25519')


def point_conversion_ea_ma(P: ECC.EccPoint):
    mu = ((1 + int(P.y)) * pow(1 - int(P.y), Ed25519.p - 2, Ed25519.p)) % Ed25519.p
    mv = ((1 + int(P.y)) * pow(((1 - int(P.y)) * int(P.x)), Ed25519.p - 2, Ed25519.p)) % Ed25519.p
    mv = (mv*(Ed25519.p - modular_sqrt(-486664, Ed25519.p))) % Ed25519.p
    return mu, mv


def point_conversion_mp_ea(U, V, W):
    U_plus_W = (U + W) % Ed25519.p
    # Montgomery trick
    T = (V * U_plus_W) % Ed25519.p
    R = pow(T, Ed25519.p - 2, Ed25519.p) # T^-1

    x = (U * R * U_plus_W * (Ed25519.p - modular_sqrt(-486664, Ed25519.p))) % Ed25519.p # U / V = U * R*(U+W) * -sqrt(486664)
    y = ((U - W) * R * V) % Ed25519.p # (U-W) / (U+W) = (U-W) * R*V

    return x, y


def point_conversion_mp_ma(U, V, W):
    inv_W = pow(W, Ed25519.p - 2, Ed25519.p) 
    u = (U * inv_W) % Ed25519.p
    v = (V * inv_W) % Ed25519.p
    return u, v

def point_conversion_ma_ea(u, v):
    x = (u * pow(v, Ed25519.p - 2, Ed25519.p)) % Ed25519.p
    y = ((u - 1) * pow(u + 1, Ed25519.p - 2, Ed25519.p)) % Ed25519.p
    x = x*(Ed25519.p - modular_sqrt(-486664, Ed25519.p)) % Ed25519.p
    return x, y


# According to https://eprint.iacr.org/2017/212.pdf Algorithm 5
# which is according to Okeya-Sakurai y-coordinate recovery algorithm 1
def y_recovery(x, y, X1, Z1, X2, Z2): # P=(x,y,1), [k]P=(X1:Z1), [k+1]P=(X2:Z2)
    t1 = (x * Z1)  % Ed25519.p
    t2 = (X1 + t1) % Ed25519.p
    t3 = (X1 - t1) % Ed25519.p
    t3 = (t3 * t3) % Ed25519.p
    t3 = (t3 * X2) % Ed25519.p

    t1 = (2*486662 * Z1) % Ed25519.p
    t2 = (t2 + t1)       % Ed25519.p
    t4 = (x * X1)        % Ed25519.p
    t4 = (t4 + Z1)       % Ed25519.p
    t2 = (t2 * t4)       % Ed25519.p

    t1 = (t1 * Z1)    % Ed25519.p
    t2 = (t2 - t1)    % Ed25519.p
    t2 = (t2 * Z2)    % Ed25519.p
    recY1 = (t2 - t3) % Ed25519.p
    t1 = (2*1 * y)    % Ed25519.p

    t1 = (t1 * Z1)    % Ed25519.p
    t1 = (t1 * Z2)    % Ed25519.p
    recX1 = (t1 * X1) % Ed25519.p
    recZ1 = (t1 * Z1) % Ed25519.p

    return recX1, recY1, recZ1


# b=256
# 3 hashes, 1 scamult, 1 coordinates conversion (1 inversion), 2 or 3 modulos, arithmetics in the end
# def my_eddsa_sign(B: ECC.EccPoint, priv_pub_key: bytearray, M: bytes):
#     #print("========== Python Sign() ==========")

#     priv_k = priv_pub_key[:32]
#     A_comp = priv_pub_key[32:]

#     L = int.from_bytes(Ed25519.L_bytes, byteorder='big')

#     #h = SHA512.new(data=priv_k).digest()                                    # 1) h = H(priv_k)
#     h = SHAKE256.new(data=priv_k).read(64)
#     s = int.from_bytes(h[0:32], byteorder='little')                         # s = h[0:32]
#                                                                             # 1.5) pruning according to RFC8032
    
#     #print('s: ', bytearray(int.to_bytes(s, length=32, byteorder="little")).hex())

#     s &= (1 << 254) - 8                                                     # clear the lowest three bits of the first octet
#     s |= (1 << 254)                                                         # set the second highest bit of the last octet (the highest bit is already clear I suppose)

#     #print("s cleared: ", hex(s))

#     #r = SHA512.new(data=(h[32:64] + M)).digest()                            # 2) r = H(k[32:64] || M)
#     r = SHAKE256.new(data=(h[32:64] + M)).read(64)
#     r = int.from_bytes(r, byteorder='little')
#     #print('r: ', bytearray(int.to_bytes(r, length=32, byteorder="little")).hex())
#     #r = r * 9
#     r = r % L                                                               # for efficiency according to RFC8032 (and now it has to be here because of mont scamult)
#     print("r_mod_l: ", bytearray(int.to_bytes(r, length=32, byteorder="little")).hex())

#                                                                             # 3) R = [r]B
#     R = r * B                                                               # just for comparison with library

#     Bmu = Ed25519.G_ma_u                                                    # precomputed generator G in Montgomery affine
#     Bmv = Ed25519.G_ma_v
#     rBmU, rBmW, r1BmU, r1BmW = _raw_curve25519(Bmu, r)                      # Curve25519 scamult, returns [r]B, [r+1]B, in Montgomery projective
#     rBmU, rBmV, rBmW = y_recovery(Bmu, Bmv, rBmU, rBmW, r1BmU, r1BmW)       # recovery of y (V) coordinate of [r]B
#     Rx, Ry = point_conversion_mp_ea(rBmU, rBmV, rBmW)                       # conversion of [r]B to Twisted Edwards affine

#     R = ECC.EccPoint(Rx, Ry, curve='Ed25519')                               
    
#     #print("R edwards (pycryptodome) scamult:    ", int(R.x), int(R.y))
#     #print("R montgomery (my conversion) scamult:", Rx, Ry)
#     print('x_ea', bytearray(int.to_bytes(Rx, length=32, byteorder="little")).hex())
#     print('y_ea', bytearray(int.to_bytes(Ry, length=32, byteorder="little")).hex())
#     #print('Rx_ea', bytearray(int.to_bytes(int(R.x) % Ed25519.p, length=32, byteorder="little")).hex())
#     #print('Ry_ea', bytearray(int.to_bytes(int(R.y) % Ed25519.p, length=32, byteorder="little")).hex())


#     R_comp = point_compress(R, Ed25519.p)                                   # 3.5) encoded R' = r*B
#     print('R_comp:', R_comp.hex())
    
#     #k = SHA512.new(data=(R_comp + A_comp + M)).digest()                     # 4) k = H(R'||A'||M)
#     k = SHAKE256.new(data=(R_comp + A_comp + M)).read(64)
#     #print("k: ", k.hex())
#     k = int.from_bytes(k, byteorder='little') % L                           # modulo for efficiency according to RFC8032
#     #print('k_mod_l: ', bytearray(int.to_bytes(k, length=32, byteorder="little")).hex())
    
#     k_mul_s = (k * s) % L
#     #print("k_mul_s: ", hex(k_mul_s))
#     S = (r + k_mul_s) % L
#     S = (r + k * s) % L                                                     # 5) S = (r + H(R'||A'||M)*s) mod l
    
#     return (R_comp + (int.to_bytes(S, length=32, byteorder='little')))      # 6) return (R, S) concatenated


def ed25519_verify(signature: bytes, A_comp: bytes, M: bytes):
    L = int.from_bytes(Ed25519.L_bytes, byteorder='big')
    B = Ed25519.G

    R_comp = signature[0:32]                                     # 1) R' = signature[0:32]
    R = point_decompress(R_comp)                                 # R = decode R' only to check if point encoding is valid
    if R is None:
        print('Error when decompressing in verify')
        return 1
    
    S = int.from_bytes(signature[32:64], byteorder='little')     # S = signature[32:64]
    if S >= int.from_bytes(Ed25519.L_bytes, byteorder='big'):
        print('Error in verify, S >= L')
        return 1
    
    A = point_decompress(A_comp)                                 # A = decode A'
    if A is None:
        print('Error when decompressing in verify')
        return 1
    
    #k = SHA512.new(data=(R_comp + A_comp + M)).digest()         # 2) k = H(R'||A'||M)
    k = SHAKE256.new(data=(R_comp + A_comp + M)).read(64)
    k = int.from_bytes(k, byteorder='little') % L
    
    SB = S * B                                                   # SB = [S]B
    kA = k * A                                                   # kA = [k]A
    R_kA = R + kA

    return 0 if SB == R_kA else 1                                # 3) [S]B == R + [k]A

def modular_sqrt(a, p):
    def legendre_symbol(a, p):
        """ Compute the Legendre symbol a|p using
            Euler's criterion. p is a prime, a is
            relatively prime to p (if p divides
            a, then a|p = 0)
            Returns 1 if a has a square root modulo
            p, -1 otherwise.
        """
        ls = pow(a, (p - 1) // 2, p)
        return -1 if ls == p - 1 else ls

    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.
        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.
        0 is returned is no square root exists for
        these a and p.
        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


# Follow the Algorithm for keypair generation from RFC 8032 of from the thesis
def ed25519_keypair_generation(priv_key: bytes):
    h = SHAKE256.new(priv_key).read(64)
    a = int.from_bytes(h[0:32], byteorder='little')
    a &= (1 << 254) - 8
    a |= (1 << 254)
    A = a * Ed25519.G
    A_comp = point_compress(A, Ed25519.p)
    res = bytearray(priv_key).copy()
    res.extend(bytearray(A_comp))
    return res


# Tests if inputed scalar multiplicated with base point yields inputed point
def ed25519_test_scamult_base(scalar: bytes, res_point_comp: bytes):
    s = int.from_bytes(scalar, byteorder='little')
    s = s % int.from_bytes(Ed25519.L_bytes, byteorder='big')
    R = s * Ed25519.G
    R_comp = point_compress(R, Ed25519.p)
    return 0 if R_comp == res_point_comp else 1
