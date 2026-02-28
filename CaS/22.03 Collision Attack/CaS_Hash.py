import CaS_midori64

def compression(message, cv):
    WK, K0, K1 = CaS_midori64.KeyGen(hex(int(message[:32], 16) ^ int(cv, 16)).replace("0x","").zfill(32))
    Y0 = CaS_midori64.Midori64_Core(cv[:16], WK, K0, K1)
    Y0 = "".join(Y0).replace("0x","")
    WK, K0, K1 = CaS_midori64.KeyGen(hex(int(message[32:64], 16) ^ int(cv, 16)).replace("0x","").zfill(32))
    Y1 = CaS_midori64.Midori64_Core(cv[16:32], WK, K0, K1)
    Y1 = "".join(Y1).replace("0x","")
    Y = Y0 + Y1
    Y = hex(int(Y, 16) ^ int(message[:32], 16) ^ int(message[32:64], 16)).replace("0x","")
    Z = Y[:8] + Y[24:32] + Y[16:24] + Y[8:16]
    return Z

def hash_core(message, cv):
    for i in range(0, len(message) // 64):
        cv = compression(message[64 * i:64 * (i + 1)], cv)
    return cv

message = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
iv = '88888888888888889999999999999999'
cv = iv
cv = hash_core(message, cv)
print("hash: " + cv)

message = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
iv = '88888888888888889999999999999999'
cv = iv
cv = hash_core(message, cv)
print("hash: " + cv)

'''
WK, K0, K1 = CaS_midori64.KeyGen("00000000000000000000000000000000")
a = CaS_midori64.Midori64_Core("8888888888888888", WK, K0, K1)
print("".join(a).replace("0x",""))
WK, K0, K1 = CaS_midori64.KeyGen("00000000000000000000000000000001")
a = CaS_midori64.Midori64_Core("8888888888888888", WK, K0, K1)
print("".join(a).replace("0x",""))
WK, K0, K1 = CaS_midori64.KeyGen("00000000000000000000000000000010")
a = CaS_midori64.Midori64_Core("8888888888888888", WK, K0, K1)
print("".join(a).replace("0x",""))
'''