from array import *

beta=[[0,0,0,1,0,1,0,1,1,0,1,1,0,0,1,1],[0,1,1,1,1,0,0,0,1,1,0,0,0,0,0,0],
                [1,0,1,0,0,1,0,0,0,0,1,1,0,1,0,1],[0,1,1,0,0,0,1,0,0,0,0,1,0,0,1,1],
                [0,0,0,1,0,0,0,0,0,1,0,0,1,1,1,1],[1,1,0,1,0,0,0,1,0,1,1,1,0,0,0,0],
                [0,0,0,0,0,0,1,0,0,1,1,0,0,1,1,0],[0,0,0,0,1,0,1,1,1,1,0,0,1,1,0,0],
                [1,0,0,1,0,1,0,0,1,0,0,0,0,0,0,1],[0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0],
                [0,1,1,1,0,0,0,1,1,0,0,1,0,1,1,1],[0,0,1,0,0,0,1,0,1,0,0,0,1,1,1,0],
                [0,1,0,1,0,0,0,1,0,0,1,1,0,0,0,0],[1,1,1,1,1,0,0,0,1,1,0,0,1,0,1,0],
                [1,1,0,1,1,1,1,1,1,0,0,1,0,0,0,0]]                
 
def KeyGen(key_128bit):
    K0 = stringToHexList(key_128bit[:16])
    K1 = stringToHexList(key_128bit[16:32])
    WK = list(int(a,16)^int(b,16) for a,b in zip(K0,K1))  
    for i in range(0,16):
        WK[i]=hex(WK[i])
    return WK,K0,K1

def KeyAdd (state, key, iteration):
    if (iteration == -1):
        state = list(int(str(a),16)^int(str(b),16) for a, b in zip(key, state))
        for i in range(0, 16):
            state[i] = hex(state[i])
    else:
        k = list(int(str(a),16) ^ int(b) for a, b in zip(beta[iteration], key))
        state = list(int(str(a),16) ^ int(b) for a, b in zip(state, k))
        for i in range(0, 16):
            state[i] = hex(state[i])
    return state

Sb0 = [0xc,0xa,0xd,0x3,0xe,0xb,0xf,0x7,0x8,0x9,0x1,0x5,0x0,0x2,0x4,0x6]
def SubCell(state):
    for i in range(16):
        state[i] = hex(Sb0[int(str(state[int(i)]),16)])
    return state

def ShuffleCell(state):
    newIndices=[0,10,5,15,14,4,11,1,9,3,12,6,7,13,2,8]
    tempState = state[:]
    for i in range(16):
        tempState[i]= state[newIndices[i]]
    return tempState

def MixColumn(state):
    cell = state[0:16]  
    for i in range(0,4):
            state[i*4]=hex(int(str(cell[i*4+1]),16) ^ int(str(cell[i*4+2]),16)^int(str(cell[i*4+3]),16))
            state[i*4+1]=hex(int(str(cell[i*4]),16) ^ int(str(cell[i*4+2]),16)^int(str(cell[i*4+3]),16))
            state[i*4+2]=hex(int(str(cell[i*4]),16) ^ int(str(cell[i*4+1]),16)^int(str(cell[i*4+3]),16))
            state[i*4+3]=hex(int(str(cell[i*4]),16) ^ int(str(cell[i*4+1]),16)^int(str(cell[i*4+2]),16))
    return state

def stringToHexList(string_input):
    hex_list = []
    for i in range(len(string_input)):
        hex_list.append(hex(int(str(string_input[i]),16)))
    return hex_list
 
def stringToIntList(string_input):
    int_list = []
    for i in range(len(string_input)):
        int_list.append(int(str(string_input[i]),16))
    return int_list

def Midori64_Core(plainText, WK, K0, K1):
    S = KeyAdd(plainText, WK,-1)
    for i in range(15):
        S = SubCell(S)
        S = ShuffleCell(S)
        S = MixColumn(S)
        S = KeyAdd(S, stringToIntList(K0 if i%2==0 else K1), i)
    S = SubCell(S)
    Y = KeyAdd(S, WK,-1)
    return Y
'''
WK, K0, K1 = KeyGen("00000000000000000000000000000000")
Y0 = Midori64_Core("0000000000000000", WK, K0, K1)
Y0 = "".join(Y0).replace("0x","")
print(Y0)
'''
'''
WK, K0, K1 = KeyGen("00000000000000000000000000000000".replace("0x","").zfill(32))
Y0 = Midori64_Core("8888888888888888", WK, K0, K1)
Y0 = "".join(Y0).replace("0x","")
print(Y0)
WK, K0, K1 = KeyGen("00000000000000000000000000000001".replace("0x","").zfill(32))
Y0 = Midori64_Core("8888888888888888", WK, K0, K1)
Y0 = "".join(Y0).replace("0x","")
print(Y0)
WK, K0, K1 = KeyGen("00000000000000000000000000000010".replace("0x","").zfill(32))
Y0 = Midori64_Core("8888888888888888", WK, K0, K1)
Y0 = "".join(Y0).replace("0x","")
print(Y0)
WK, K0, K1 = KeyGen("00000000000000000000000000000011".replace("0x","").zfill(32))
Y0 = Midori64_Core("8888888888888888", WK, K0, K1)
Y0 = "".join(Y0).replace("0x","")
print(Y0)
'''
'''
unfix = "0000000000000000000000000000000000000000000000000000000000000000"
default = "8888888888888888888888888888888888888888888888888888888888888888"
for i in range(256):
    data = hex(int(unfix,16) + int(default, 16)).replace("0x","").zfill(64)
    WK, K0, K1 = KeyGen(hex(int(data[:32], 16) ^ int("88888888888888889999999999999999", 16)).replace("0x","").zfill(32))
    Y0 = Midori64_Core("8888888888888888", WK, K0, K1)
    Y0 = "".join(Y0).replace("0x","")
    WK, K0, K1 = KeyGen(hex(int(data[32:64], 16) ^ int("88888888888888889999999999999999", 16)).replace("0x","").zfill(32))
    Y1 = Midori64_Core("9999999999999999", WK, K0, K1)
    Y1 = "".join(Y1).replace("0x","")
    Y = Y0 + Y1
    Y = hex(int(Y, 16) ^ int(data[:32], 16) ^ int(data[32:64], 16)).replace("0x","")
    Z = Y[:8] + Y[24:32] + Y[16:24] + Y[8:16]
    print(Z)
    unfix = bin(int(unfix, 2) + 1)[2:].zfill(64)
'''
'''
key_128Bit = "687ded3b3c85b3f35b1009863e2a8cbf"
WK, K0, K1 = KeyGen(key_128Bit)
plainText = "42c20fd3b586879e"
expected_output = "66bcdc6270d901cd"
print("Output from Algorithm: ", *Midori64_Core(plainText, WK, K0, K1))
print("Expected Output      : ", *stringToHexList(expected_output))
'''
