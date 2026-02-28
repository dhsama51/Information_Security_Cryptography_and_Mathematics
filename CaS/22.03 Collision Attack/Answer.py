import random
from unittest.main import main
import random
import time
import pickle
#right가 fixed. (전수조사하고, 돌릴 때 바뀐다.)
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

def collision0():
    print("start")
    msg = "8888888888888888"
    right = ""
    for i in range(16): #right 만들어주는 부분
        right = right + str(random.randrange(0,2))#right를 생성해둔다.
    msg_list = []
    while(1):
        left = ""
        for i in range(16):
            left = left + str(random.randrange(0,2))
        left = left + right
        if left in msg_list:
            continue
        msg_list.append(left)
        if len(msg_list) == 256:
            print("msg_list 생성완료")
            break
    cip_list = []
    
    for i in range(len(msg_list)):
        tmp = ""
        wk, k0, k1 = KeyGen(msg_list[i])
        cip = Midori64_Core(msg, wk, k0, k1)
        for j in range(len(cip)):
            tmp = tmp + cip[j][2]
        cip_list.append(tmp)
    print("cip_list 생성완료")
    for i in range(len(cip_list)):
        if cip_list[i] in cip_list[i+1:]:
            index_of_cip_coll = cip_list[i+1:].index(cip_list[i])+1+i
            print("ciphertext0 = ", cip_list[i])
            print("ciphertext1 = ", cip_list[index_of_cip_coll])
            print("msg0 = ", msg_list[i])
            print("msg1 = ", msg_list[index_of_cip_coll])
            print("------------------------------")

def collision1():
    ciphertext0 =  "8988999899998998"
    ciphertext1 =  "8988999899998998"
    msg = "9999999999999999"
    msg0 =  "01101001011001111001010011111000"
    msg1 =  "11111001101000101001010011111000"

    #msg가 888~8 인거랑 999~9인거랑 암호문의 차이가 비트반전밖에 없다.
    #--------
    wk, k0, k1 = KeyGen(msg0)
    cip0 = Midori64_Core(msg, wk, k0, k1)
    wk, k0 ,k1 = KeyGen(msg1)
    cip1 = Midori64_Core(msg, wk, k0, k1)
    print(cip0)
    print(cip1)
    if cip0 == cip1:
        print("anjwl")
    

    #--------
    # ciphertext0 =  "8898899988998898"
    # ciphertext1 =  "8898899988998898"
    # msg0 =  "11011001101110100110110111001001"
    # msg1 =  "11101110001101010110110111001001"

    msg0 = msg0[:16]
    msg1 = msg1[:16]
    msg_diff = int(msg0, 16) ^ int(msg1, 16)#왼쪽64비트만 차분
    right = ""
    for i in range(16):
        right = right + str(random.randrange(0,2))
    cnt = 0
    for i in range(1):
        left0 = ""
        for j in range(16):
            left0 = left0 + str(random.randrange(0,2))
        
        #print("left0 = ", left0)
        left1 = int(left0, 16) ^ msg_diff
        left1 = hex(left1)[2:].zfill(16)
        left0 = left0 + right
        left1 = left1 + right
        wk, k0, k1 = KeyGen(left0)
        cip0 = Midori64_Core(msg, wk, k0, k1)
        tmp0 = ""
        tmp1 = ""
        for j in range(len(cip0)):
            tmp0 = tmp0 + cip0[j][2]
        wk, k0 ,k1 = KeyGen(left1)
        cip1 = Midori64_Core(msg, wk, k0, k1)
        for j in range(len(cip1)):
            tmp1 = tmp1 + cip1[j][2]
        if cip0 == cip1:
            print("left0 = ", left0)
            print("left1 = ", left1)
            print("cip0 = ", tmp0)
            print("cip1 = ", tmp1)
            print("------------------")
            
    print("cnt = ", cnt)
        
def check():
    iv = "88888888888888889999999999999999"
    #result
    msg0 =  "01101001011001111001010011111000"
    msg1 =  "11111001101000101001010011111000"
    ciphertext0 =  "8988999899998998"
    ciphertext1 =  "8988999899998998"
    #--------------------------
    left0 =  "11010010010011011010110111101011"
    left1 =  "01000010100010001010110111101011"
    cip0 =  "8888988889898888"
    cip1 =  "8888988889898888"
    #--------------------------
    #check
    msg_up = "8888888888888888"
    msg_down = "9999999999999999"
    #--pair0--
    pair0_key_up = "01101001011001111001010011111000" #msg0
    pair0_key_down = "11010010010011011010110111101011" #left0
    pair0_cip_up = "8988999899998998"#ciphertext0
    pair0_cip_down = "8888988889898888"#cip0
    #--pair1--
    pair1_key_up = "11111001101000101001010011111000"
    pair1_key_down = "01000010100010001010110111101011"
    pair1_cip_up = "8988999899998998"
    pair1_cip_down = "8888988889898888"
    #---total stting---
    p0_m01234567 = "0110100101100111100101001111100011010010010011011010110111101011"
    p1_m01234567 = "1111100110100010100101001111100001000010100010001010110111101011"





    #--------------------------
    pair0_m0123 = int(pair0_key_up, 16) ^ int(iv, 16)
    pair0_m4567 = int(pair0_key_down, 16) ^ int(iv, 16)
    pair0_c0123 = int(pair0_cip_up + pair0_cip_down, 16)
    pair0_cv = pair0_m0123 ^ pair0_m4567 ^ pair0_c0123

    pair1_m0123 = int(pair1_key_up, 16) ^ int(iv, 16)
    pair1_m4567 = int(pair1_key_down, 16) ^ int(iv, 16)
    pair1_c0123 = int(pair1_cip_up + pair1_cip_down, 16)
    pair1_cv = pair1_m0123 ^ pair1_m4567 ^ pair1_c0123

    print(hex(pair0_cv))
    print(hex(pair1_cv))

def compression_function(msg, cv):
    cv128_int = int(cv, 16)
    cv01 = cv[:16]
    cv23 = cv[16:]
    m = msg
    m0123 = m[:32]
    m4567 = m[32:]
    m0123_int = int(m0123,16)
    m4567_int = int(m4567,16)
    cv01_int = int(cv01, 16)
    cv23_int = int(cv23, 16)
    m0123_int = m0123_int ^ cv128_int
    m4567_int = m4567_int ^ cv128_int
    m0123_str = hex(m0123_int)[2:].zfill(32)
    m4567_str = hex(m4567_int)[2:].zfill(32)
    
    #gen ciphertext1
    wk_1, k0_1, k1_1 = KeyGen(m0123_str)
    ciphertext1 = Midori64_Core(cv01, wk_1, k0_1, k1_1)
    #print("ciphertext1 = ", ciphertext1)

    #gen ciphertext2
    wk_2, k0_2, k1_2 = KeyGen(m4567_str)
    ciphertext2 = Midori64_Core(cv23, wk_2, k0_2, k1_2)
    #print("ciphertext2 = ", ciphertext2)
    tmp_ciphertext1 = ""
    tmp_ciphertext2 = ""
    for i in range(16):
        tmp_ciphertext1 = tmp_ciphertext1 + ciphertext1[i][2]
    for i in range(16):
        tmp_ciphertext2 = tmp_ciphertext2 + ciphertext2[i][2]
    
    cv0123 = int(tmp_ciphertext1 + tmp_ciphertext2, 16)
    cv0123 = cv0123 ^ int(m0123, 16) ^ int(m4567,16)
    
    cv0123_str = hex(cv0123)[2:]    
    output = cv0123_str[:8] + cv0123_str[24:32] + cv0123_str[16:24] + cv0123_str[8:16]

    return output
def advance():
    cv0 = "8888888888888888"
    cv1 = "9999999999999999"
    msg0 =  "01101001011001111001010011111000"
    msg1 =  "11111001101000101001010011111000"
    cip0 = []
    key0 = []
    for i in range(2**8):
        key = ""
        for i in range(32):
            key = key + str(random.randrange(2))
        key0.append(key)
        wk, k0, k1 = KeyGen(key)
        tmp = Midori64_Core(cv0, wk, k0, k1)
        cip0.append(tmp)
    for i in range(len(cip0)):
        if cip0[i] in cip0[i+1:]:
            idx = cip0[i+1:].index(cip0[i]) + i + 1
            print("ciphertext = ", cip0[i])
            print("key0 = ", key0[i])
            print("key1 = ", key0[idx])
def collllll():
    ciphertext =  ['0x8', '0x8', '0x8', '0x9', '0x9', '0x8', '0x8', '0x9', '0x8', '0x8', '0x8', '0x9', '0x9', '0x8', '0x8', '0x8']
    key0 =  "11111001001011101101000010010110"
    key1 =  "10011101000010101100001101000000"
    cv0 = "8888888888888888"
    cv1 = "9999999999999999"

    wk, k0, k1 = KeyGen(key0)
    cip0 = Midori64_Core(cv0, wk, k0, k1)
    wk, k0, k1 = KeyGen(key1) 
    cip1 = Midori64_Core(cv0, wk, k0, k1)

    print(cip0)
    print(cip1)
    if cip0==cip1:
        print("coll")

    print("-----------")
    print(hex(int(key0, 16) ^ 0x88888888888888889999999999999999))
    print(hex(int(key1, 16) ^ 0x88888888888888889999999999999999))

    
    


        

if __name__ == '__main__':
    #collision0()
    #collision1()
    #check()
    #advance()
    collllll()

    #---------------------------------------------
    # iv = "88888888888888889999999999999999"
    # p0_m01234567 = "8998988989988999899898998888899999898898898899898989889888898988"
    # p1_m01234567 = "9999988998988898899898998888899989888898988898888989889888898988"
    # p0_m0123 = p0_m01234567[:32]
    # p0_m4567 = p0_m01234567[32:]
    # p1_m0123 = p1_m01234567[:32]
    # p1_m4567 = p1_m01234567[32:]

    # p0_cv = compression_function(iv, p0_m01234567)
    # print(p0_cv)
    # p1_cv = compression_function(iv, p1_m01234567)
    # print(p1_cv)

    # if p0_cv == p1_cv:
    #     print("collision")

    #----------------------------------
    # test_msg = "0000000000000000000000000000000000000000000000000000000000000000"
    # print(len(test_msg))
    # a = compression_function(iv, test_msg)
    # print(a)
    # b = compression_function(a, test_msg)
    # print(b)
    #위의 블록에서 충돌이 발생하는 차분을 찾고 이 차분을 아래 블록에서 그래도 적용을 시키면 충돌이 발생한다?
    print(compression_function("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "88888888888888889999999999999999"))