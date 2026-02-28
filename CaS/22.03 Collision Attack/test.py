import CaS_midori64


for j in range(16):
    A = ['0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8']
    B = ['0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8', '0x8']
    
    if A[j] == '0x8':
        A[j] = '0x9'
    else:
        A[j] = '0x8'
    for i in range(15):
        A = CaS_midori64.ShuffleCell(A)
        #print(i + 1, end = "")
        #print(": ", end = "")
        #print(A)
        A = CaS_midori64.MixColumn(A)
        #print(i + 1, end = "")
        #print(": ", end = "")
        #print(A)
        if A[j] == '0x8' and i % 2 == 1:
            A[j] = '0x9'
        elif A[j] == '0x9' and i % 2  == 1:
            A[j] = '0x8'
    if A[j] == '0x8':
        A[j] = '0x9'
    else:
        A[j] = '0x8'
    
    for i in range(15):
        B = CaS_midori64.ShuffleCell(B)
        B = CaS_midori64.MixColumn(B)
    A = "".join(A).replace("0x","")
    B = "".join(B).replace("0x","")
    print(hex(int(A, 16)^int(B, 16)).replace("0x","").zfill(16))
#print(A)
#print(B)
#print(hex(int(A, 16)^int(B, 16)).replace("0x","").zfill(16))