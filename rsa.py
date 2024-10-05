import random

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def sqrtmod(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

def addpoint(P, Q):
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P

    if P == Q:
        lda = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p)
    elif P[0] == Q[0]:
        return (0, 0)
    else:
        lda = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p)

    xr = (lda * lda - P[0] - Q[0]) % p
    yr = (lda * (P[0] - xr) - P[1]) % p
    return (xr, yr)

def multpoint(s, P):
    if s == 0:
        return (0, 0)
    elif s == 1:
        return P

    N = P
    Q = (0, 0)
    while s:
        if s & 1:
            Q = addpoint(Q, N)
        N = addpoint(N, N)
        s >>= 1
    return Q

def qround(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] ^= x[a]
    x[d] = ((x[d] << 16) | (x[d] >> 16)) & 0xffffffff

    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] ^= x[c]
    x[b] = ((x[b] << 12) | (x[b] >> 20)) & 0xffffffff

    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] ^= x[a]
    x[d] = ((x[d] << 8) | (x[d] >> 24)) & 0xffffffff

    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] ^= x[c]
    x[b] = ((x[b] << 7) | (x[b] >> 25)) & 0xffffffff

def cblock(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    kwords = [int.from_bytes(key[i:i+4], 'little') for i in range(0, 32, 4)]
    cntwords = [counter]
    nwords = [int.from_bytes(nonce[i:i+4], 'little') for i in range(0, 12, 4)]

    state = constants + kwords + cntwords + nwords
    wstate = state[:]

    for _ in range(10):
        qround(wstate, 0, 4, 8, 12)
        qround(wstate, 1, 5, 9, 13)
        qround(wstate, 2, 6, 10, 14)
        qround(wstate, 3, 7, 11, 15)
        qround(wstate, 0, 5, 10, 15)
        qround(wstate, 1, 6, 11, 12)
        qround(wstate, 2, 7, 8, 13)
        qround(wstate, 3, 4, 9, 14)

    return [(wstate[i] + state[i]) & 0xffffffff for i in range(16)]

def chacipher(key, nonce, counter, data):
    result = bytearray()

    for i in range(0, len(data), 64):
        block = cblock(key, counter, nonce)
        keystream = b''.join(b.to_bytes(4, 'little') for b in block)
        bsize = min(64, len(data) - i)
        result += bytes(a ^ b for a, b in zip(data[i:i+bsize], keystream[:bsize]))
        counter += 1

    return result

def encrypt(plaintext):
    nonce = hex(random.getrandbits(96))[2:].zfill(24)     
    noncebytes = bytes.fromhex(nonce)
    ciphertext = nonce + '9c' + chacipher(keybytes, noncebytes, counter, plaintext).hex()
    return ciphertext

def decrypt(ciphertext):
    nonce = bytes.fromhex(ciphertext[:24])
    ctext = bytes.fromhex(ciphertext[26:])
    decrypted = chacipher(keybytes, nonce, counter, ctext).decode('utf-8')
    return decrypted

def start():
    global otherpubkey, seckey, key, keybytes, counter
    counter = 1
    txt = input('> ')
    if len(txt) == 70 and txt[64:69] == 'b96ef':
        otherpubkey = newpubkey(int(txt[:64], 16), txt[-1])
        seckey = multpoint(privkey, otherpubkey)
        key = hex(seckey[1])[2:].zfill(64)
        keybytes = bytes.fromhex(key)
        print(otherpubkey)
        print(seckey)
    elif len(txt) > 26 and txt[24:26] == '9c':
        print(decrypt(txt))
    else:
        print(encrypt(txt.encode('utf-8')))

def change():
    global privkey, pubkey, otherpubkey
    privkey = random.randint(1, n-1)
    pubkey = multpoint(privkey, G)
    print(pubkey)
    # print(f'Private Key: {privkey}')
    print(f'Public Key: {hex(pubkey[0])[2:].zfill(64)}b96ef{pubkey[1] % 2}')
    return multpoint(privkey, otherpubkey)

def newpubkey(pubkey, parity):
    y1 = sqrtmod(pow(pubkey, 3, p) + a * pubkey + b, p)
    if (parity == '1' and y1 % 2 == 1) or (parity == '0' and y1 % 2 == 0):
        return (pubkey, y1)
    else:
        return (pubkey, p - y1)

a, b, p = 0, 7, 115792089237316195423570985008687907853269984665640564039457584007908834671663
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240, \
     32670510020758816978083085130507043184471273380659243275938904335757337482424)
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
otherpubkey = (0, 0)
seckey = 0

print('change my key (y/n)?')
changekey = input('> ')
if changekey == 'y':
    seckey = change()

key = hex(seckey[1])[2:].zfill(64)
keybytes = bytes.fromhex(key)
while True:
    start()
