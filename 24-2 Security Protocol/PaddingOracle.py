from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import time
import hashlib
import hmac

BUFFER_SIZE = 65536 # 수정 금지
#프로토콜 정의
protocol={0:"ClientHello",
          1:"ServerHello",
          2:"Certificate",
          3:"ServerHelloDone",
          4:"ClientKeyExcnage",
          5:"ChangeCipherSpec",
          6:"Finished",
          255:"Error code", 
          254:"ECHO Mode", 
          253:"Data Decryption Mode"}
protocol_str={"ClientHello":0,
            "ServerHello":1,
            "Certificate":2,
            "ServerHelloDone":3,
            "ClientKeyExcnage":4,
            "ChangeCipherSpec":5,
            "Finished":6,
            "Error code":255,
            "ECHO Mode":254,
            "Data Decryption Mode":253}

#for debug
#주고 받은 데이터를 출력하기 위한 디버깅용 함수
def print_packet(additional,data,enc=False):
    if enc:
        print (f"{additional} (raw)", data)
        print (f"{additional} (hex)", data.hex())
    else:
        protocol={0:"ClientHello",1:"ServerHello",2:"Certificate",3:"ServerHelloDone",4:"ClientKeyExcnage",5:"ChangeCipherSpec",6:"Finished",255:"Error code", 254:"ECHO Mode", 253:"Data Encryption Mode", 252:"Data Decryption Mode"}
        p = data[0]
        msg_len = int.from_bytes(data[1:5],"little")
        msg = data[5:5+msg_len]
        mac = data[5+msg_len:]
        ret = {"protocol":protocol[p], "Message_len":msg_len,"Message(bytes)":msg,"Message(Hex)":msg.hex(),"MAC":mac}
        import pprint
        print(f"{additional}")
        pprint.pprint(ret)    
    









####################################################################
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
#MINI TLS start
def start_mini_tls(server:socket):
    # 구현필요
    # 송신 (send_data 함수 사용)
    # 통신1. 난수 생성1. client_random = 
    # 통신1. Clienthello 송신(client_random)
    '''''''''''''''''''''직접 구현한 부분 시작'''''''''''''''''''''''''''
    '''통신 1'''
    '''32byte 난수값을 생성해 client_random으로 사용'''
    '''길이가 32byte가 아니면 프로그램 종료'''
    client_random = gen_random(32)
    if len(client_random) != 32:
        print("생성된 client_random이 32byte가 아니었습니다.")
        exit(0)
    send_data(server, 0, client_random)
    '''''''''''''''''''''직접 구현한 부분 끝'''''''''''''''''''''''''''
   
    
    # 수신 (get_dat 함수 사용)
    # 통신2. ServerHello 수신(서버 난수) server_random = 
    #
    # 통신3. Certificate 수신(서버 인증서) #base64 인코딩 되어있으며, 디코딩없이 그대로 사용 가능 RSA_Encrypt 함수 사용 cp =  RSA_Encrypt(pub,pt)
    #
    # 통신4. ServerHelloDone 수신()
    
    '''''''''''''''''''''직접 구현한 부분 시작'''''''''''''''''''''''''''
    '''통신 2'''
    '''protocol 확인: ServerHello가 아니면 프로그램 종료'''
    '''length 확인: get_data()에서 확인하므로 패스'''
    '''server_random 확인: 32byte가 아니면 프로그램 종료'''
    protocol, length, server_random = get_data(server)
    if protocol != 1:
        print("프로토콜이 ServerHello(1)가 아니었습니다.")
        exit(0)
    if len(server_random) != 32:
        print("받은 server_random이 32byte가 아니었습니다.")
        exit(0)

    '''통신 3'''
    '''protocol 확인: Certificate가 아니면 프로그램 종료'''
    '''length 확인: get_data()에서 확인하므로 패스'''
    '''certificate 확인: 인증서는 애초에 신뢰의 대상이므로 검증할 필요 없음'''
    protocol, length, certificate = get_data(server)
    if protocol != 2:
        print("프로토콜이 Certificate(2)가 아니었습니다.")
        exit(0)
    
    '''통신 4'''
    '''protocol 확인: ServerHelloDone가 아니면 프로그램 종료'''
    '''length 확인: get_data()에서 확인하므로 패스'''
    '''ServerHelloDone 확인: 01이 아니면 프로그램 종료'''
    protocol, length, temp = get_data(server)
    if protocol != 3:
        print("프로토콜이 ServerHelloDone(3)이 아니었습니다.")
        exit(0)
    if(temp.hex() != '01'):
        print(f"ServerHelloDone의 값이 01이 아닌 {temp}이었습니다.")
        exit(0)
    '''''''''''''''''''''직접 구현한 부분 끝'''''''''''''''''''''''''''

    # 송신 (send_data 함수 사용)
    # 통신5. 난수 생성2. PreMasterSecret = 
    # 통신5. 생성한 난수를 서버의 인증서로 암호화 Encrypted_PreMasterSecret =  RSA_Encrypt(pub,PreMasterSecret)
    # 통신5. ClientKeyExchange 송신(Encrypted_PreMasterSecret)
    # 
    # - PreMasterSecret, client_random, server_random을 활용한 MasterSecret 생성
    #    Hint.   HKDF(PreMasterSecret,"master secret",client_random,server_random,48)
    #
    # - MasterSecret을 활용한 KEYBLOB 생성
    #    Hint.   HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    #
    # - KEYBLOB 분리 (Client_MAC_KEY, Server_MAC_KEY, Client_Cipher_KEY, Server_Cipher_KEY, Client_Cipher_IV, Server_Cipher_IV)
    #
    # 통신6. ChangeCipherSepc 송신(0x1)
    #
    # 통신7. Finished 송신(0x1) 
    
    '''''''''''''''''''''직접 구현한 부분 시작'''''''''''''''''''''''''''
    '''통신 5'''
    '''32byte 난수값 생성해 PreMasterSecret로 사용'''
    '''client_random, server_random, PreMasterSecret이 있으므로 HKDF 함수를 이용해 MasterSecret 생성'''
    PreMasterSecret = gen_random(32)
    Encrypted_PreMasterSecret = RSA_Encrypt(certificate, PreMasterSecret)
    MasterSecret = HKDF(PreMasterSecret, "master secret", client_random, server_random, 48)

    '''암호화된 PreMasterSecret 전송'''
    send_data(server, 4, Encrypted_PreMasterSecret)
    
    '''MasterSecret을 활용해 KEYBLOB 생성, 분리'''
    BLOB = HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    Client_MAC_KEY = BLOB[0:16]
    Server_MAC_KEY = BLOB[16:32]
    Client_Cipher_KEY = BLOB[32:48]
    Server_Cipher_KEY = BLOB[48:64]
    Client_Cipher_IV = BLOB[64:80]
    Server_Cipher_IV = BLOB[80:96]

    '''통신 6'''
    '''서버로 ChangeCipherSpec 값인 01 전송'''
    send_data(server, 5, bytes.fromhex('01'))

    '''통신 7'''
    '''서버로 Finished 값인 01 전송'''
    send_data(server, 6, bytes.fromhex('01'))
    '''''''''''''''''''''직접 구현한 부분 끝'''''''''''''''''''''''''''

    # 수신 (get_dat 함수 사용)
    # 통신8. ChangeCipherSpec 수신(0x1)
    #
    # 통신9. Finished 송신(0x1) 
    
    '''''''''''''''''''''직접 구현한 부분 시작'''''''''''''''''''''''''''
    '''통신 8'''
    '''protocol 확인: ChangeCipherSpec가 아니면 프로그램 종료'''
    '''length 확인: get_data()에서 확인하므로 패스'''
    '''ChangeCipherSpec 확인: 01이 아니면 프로그램 종료'''
    protocol, length, temp = get_data(server)
    if protocol != 5:
        print("프로토콜이 ChangeCipherSpec(5)이 아니었습니다.")
        exit(0)
    if(temp.hex() != '01'):
        print(f"ChangeCipherSpec의 값이 01이 아니라 {temp}이었습니다.")
        exit(0)

    '''통신 9'''
    '''protocol 확인: Finished가 아니면 프로그램 종료'''
    '''length 확인: get_data()에서 확인하므로 패스'''
    '''Finished 확인: 01이 아니면 프로그램 종료'''
    protocol, length, temp = get_data(server)
    if protocol != 6:
        print("프로토콜이 Finished(6)가 아니었습니다.")
        exit(0)
    if(temp.hex() != '01'):
        print(f"Finished의 값이 01이 아니라 {temp}이었습니다.")
        exit(0)
    '''''''''''''''''''''직접 구현한 부분 끝'''''''''''''''''''''''''''

    # 핸드셰이크 종료
    
    '''''''''''''''''''''직접 구현한 부분 시작'''''''''''''''''''''''''''
    '''DECRYPT MODE로 진입'''
    '''복호화된 키는 a25c47d7350b828e7f83d9f66d049d0239 ea08bd87b6148a0808080808080808'''
    decrypted = DECRYPT_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)
    '''이미지 복호화'''
    decrypted = bytes.fromhex(decrypted[:48])
    DECRYPT_IMAGE(decrypted)
    ''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''



''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''직접 구현한 부분 시작'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

def DECRYPT_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    given_iv = '0866e37ebbb7f729ca2e512a26c1e2d7' #주어진 값 저장
    given_ciphertext = 'd9b9287788dbbd6649702cc2fb8a8454e313da1bf68e4c7314ba01735262148e'
    given_full = given_iv + given_ciphertext
    plaintext = list(given_ciphertext) #초기값=암호문, 복호화되면 부분 업데이트
    
    '''cal_pad에서 구한 패딩 길이를 복호화 알고리즘에 넣어줌'''
    print(f"\n\n**이진 탐색으로 패딩 길이를 구합니다.")
    pad_len = cal_pad(given_ciphertext, server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)
    print(f"\n**본격적인 복호화를 시작합니다.")
    result = decrypt_algorithm(pad_len, given_iv, given_ciphertext, given_full, plaintext, server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)
    return result

def cal_pad(given_ciphertext, server, Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    low, high = 0, 15
    given_ciphertext = list(given_ciphertext)
    while True:
        mid = (low+high) // 2
        temp = int(''.join(given_ciphertext[2*mid:2*mid+2]), 16) ^ 0x01 #범위의 가운데 byte 변조
        given_ciphertext[2*mid:2*mid+2] = f"{temp:02x}"

        send_msg = bytes.fromhex(''.join(given_ciphertext)) #메시지 송신, 수신
        send_attack_enc_data(server, 253, send_msg, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV)
        protocol, msg_len, msg, mac = get_attack_enc_data(server, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)
        print(f"*마지막 블록의 {mid+1}번째 바이트 변조")
        print(f"보낸 메시지          | {send_msg.hex()}")
        print(f"받은 메시지          | {msg.decode()}")
        
        temp = int(''.join(given_ciphertext[2*mid:2*mid+2]), 16) ^ 0x01 #변조했던 바이트 되돌리기
        given_ciphertext[2*mid:2*mid+2] = f"{temp:02x}"

        if msg.decode() == 'OK+':
            if mid + 1 > high:
                print(f"특이 사항            | 패딩의 길이를 알아냈습니다! {high}byte만큼이 패딩입니다.\n")
                return low
            else:
                low = mid + 1
                print(f"보낸 메시지          | 패딩의 끝이 변조한 위치보다 오른쪽에 있습니다.\n")
        else:
            if low > mid - 1:
                print(f"특이 사항            | 패딩의 길이를 알아냈습니다! {low}byte만큼이 패딩입니다.\n")
                return high
            else:
                high = mid - 1
                print(f"보낸 메시지          | 패딩의 끝이 변조한 위치보다 왼쪽에 있습니다.\n")

def decrypt_algorithm(pad_len, given_iv, given_ciphertext, given_full, plaintext, server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    '''암호문의 각 block 순회 -> 암호문 크기: 32byte = 16byte * 2개 -> 총 2번 반복'''
    '''IV는 암호문의 첫 번째 블록과 XOR 연산 -> 1block = 16byte'''
    block_num = len(given_ciphertext) // 32
    for each_block in range(block_num):
        bl_p = -32*each_block #복호화할 block 설정 -> index 조절
        iv = given_full[bl_p-64:bl_p-32 or None]
        cipher_block = given_full[bl_p-32:bl_p or None]
        iv_prime = list(iv) #iv_prime에서 iv를 조작해서 전송
        iv_xor_plaintext = list(f"{int(iv, 16) ^ int(''.join(plaintext[bl_p-32:bl_p or None]), 16):02x}") #패딩값 조작을 쉽게 하기 위해 iv_xor_plaintext를 계산해서 저장
        candidate=['0'] #후보키를 세는 list를 생성해서 사용
        
        if each_block == 0:
            pad = f"{pad_len:02x}" * pad_len
            plaintext[-2*pad_len:] = pad

            iv_xor_plaintext[bl_p-32:bl_p or None] = f"{(int(iv, 16) ^ int(''.join(plaintext[bl_p-32:bl_p or None]), 16)):02x}"

            print(f"*특이 사항           | 패딩 길이만큼 복호화하고 브루트 포스를 시작합니다.")
            print(f"기존 ciphertext      | {given_ciphertext}")
            print(f"패딩 길이만큼 복호화 | {''.join(plaintext)}")

        '''블록의 각 byte 순회 -> 블록 크기: 16byte = 1byte * 16개 -> 총 16번 반복 + 복호화를 위해 1번 더 루프'''
        '''마지막 루프에서는 평문 복호화한 후 break'''
        for each_byte in range(17):
            by_p = -2*each_byte #복호화할 byte 설정 -> index 조절
            bl_p -= 2 #by_p 따라 bl_p도 조절
            is_1st_cand_true = 0 #후보키가 2개일 때 1번째 시도 성공 여부 확인 flag -> 다음 키 사용 여부에 활용

            if each_block==0 and each_byte < pad_len: #패딩 길이로 알아낸 부분은 패스
                continue

            '''끝 byte 다음 루프에서만 후보키 개수만큼 루프, 나머지는 어차피 후보키 1개이므로 1로 고정'''
            '''복호화->패딩 세팅->브루트 포스 순서로 진행'''
            for each_can in range(1 if each_byte!=1 else len(candidate)):
                if each_byte == 0 or (each_block == 0 and each_byte == pad_len): #끝 byte 루프. 복호화할 게 없으므로 임시 원소 제거 후 진행
                    del candidate[0]

                elif each_byte == 1: #끝에서 2번째 byte 루프. 4가지 케이스로 나뉨...
                    if each_can == 0: #1번째 시도(후보키가 애초에 1개였거나 후보키 2개 중 1번 키로 시도하는 경우)
                        if len(candidate) == 2: #후보키가 2개 중 1번 키로 시도하는 경우
                            iv_xor_plaintext[by_p:by_p+2 or None] = candidate[0]
                            plaintext[bl_p+2:bl_p+4 or None] = f"{(int(''.join(iv_xor_plaintext)[by_p:by_p+2 or None], 16) ^ int(iv[by_p:by_p+2 or None], 16)):02x}"
                            print(f"                     | 2개의 후보키 중 1번 후보키를 사용하여 복호화합니다.")
                            print(f"시도한 후보키        | {candidate[0]}")
                            print(f"기존 ciphertext      | {given_ciphertext}")
                            print(f"1번 후보키로 복호화  | {''.join(plaintext)}\n")
                            del candidate[0]
                        else: #끝 block임에도 후보키가 1개인 경우
                            iv_xor_plaintext[by_p:by_p+2 or None] = candidate[0]
                            plaintext[bl_p+2:bl_p+4 or None] = f"{(int(''.join(iv_xor_plaintext)[by_p:by_p+2 or None], 16) ^ int(iv[by_p:by_p+2 or None], 16)):02x}"
                            print(f"                     | 끝 block임에도 후보키가 1개여서 바로 복호화가 가능했습니다.")
                            print(f"기존 ciphertext      | {given_ciphertext}")
                            print(f"일부 복호화한 결과   | {''.join(plaintext)}\n")
                            del candidate[0]
                    else: #2번째 시도(1번째 시도가 맞았거나 틀린 경우)
                        if is_1st_cand_true:
                            print(f"                     | 후보키 중 먼저 시도했던 키가 맞았습니다. 남은 후보키를 버리고 다음 byte로 넘어갑니다.")
                            del candidate[0]
                            break
                        else:
                            iv_xor_plaintext[by_p:by_p+2 or None] = candidate[0]
                            plaintext[bl_p+2:bl_p+4 or None] = f"{(int(''.join(iv_xor_plaintext)[by_p:by_p+2 or None], 16) ^ int(iv[by_p:by_p+2 or None], 16)):02x}"
                            print(f"                     | 후보키 중 먼저 시도했던 키가 틀렸습니다. 남은 후보키를 사용합니다.")
                            print(f"시도한 후보키        | {candidate[0]}")
                            print(f"기존 ciphertext      | {given_ciphertext}")
                            print(f"남은 후보키로 복호화 | {''.join(plaintext)}\n")
                            del candidate[0]

                elif each_byte == 16: #마지막 루프. 복호화만 하고 break
                    iv_xor_plaintext[by_p:by_p+2 or None] = candidate[0]
                    plaintext[bl_p+2:bl_p+4 or None] = f"{(int(''.join(iv_xor_plaintext)[by_p:by_p+2 or None], 16) ^ int(iv[by_p:by_p+2 or None], 16)):02x}"
                    print(f"기존 ciphertext      | {given_ciphertext}")
                    if each_block + 1 != block_num:
                        print(f"1개 블록 복호화 완료!| {''.join(plaintext)}\n")
                    if each_block + 1 == block_num:
                        print(f"완전히 복호화 완료!! | {''.join(plaintext)}\n")
                    del candidate[0]
                    break

                else: #나머지 경우. 복호화 후 계속 진행
                    iv_xor_plaintext[by_p:by_p+2 or None] = candidate[0]
                    plaintext[bl_p+2:bl_p+4 or None] = f"{(int(''.join(iv_xor_plaintext)[by_p:by_p+2 or None], 16) ^ int(iv[by_p:by_p+2 or None], 16)):02x}"
                    print(f"기존 ciphertext      | {given_ciphertext}")
                    print(f"일부 복호화한 결과   | {''.join(plaintext)}\n")
                    del candidate[0]
                    

                for back in range(0, each_byte): #브루트 포스 진행을 위해 뒤 바이트 패딩값 세팅
                    lo = -2-2*back
                    temp = int(''.join(iv_xor_plaintext)[lo:lo+2 or None], 16) ^ (each_byte + 1)
                    iv_prime[lo:lo + 2 or None] = f"{temp:02x}"
            
                '''byte가 가질 수 있는 값 전부 대입 -> 0~255 -> 총 256번 반복'''
                for in_byte in range(256):
                    if each_block == 0: #옳은 패딩을 만드는 값을 기록해 놓았음. 주석처리하면 브루트 포스 수행
                        if ((each_byte == 0 and not (in_byte == 0x54 or in_byte == 0x5d)) or (each_byte == 1 and in_byte != 0x8e) or (each_byte == 2 and in_byte != 0x81) or (each_byte == 3 and in_byte != 0xf7)
                            or (each_byte == 4 and in_byte != 0xcf) or (each_byte == 5 and in_byte != 0x22) or (each_byte == 6 and in_byte != 0x7f) or (each_byte == 7 and in_byte != 0x49)
                            or (each_byte == 8 and in_byte != 0xe5) or (each_byte == 9 and in_byte != 0xa3) or (each_byte == 10 and in_byte != 0x66) or (each_byte == 11 and in_byte != 0x03)
                            or (each_byte == 12 and in_byte != 0xc7) or (each_byte == 13 and in_byte != 0x2e) or (each_byte == 14 and in_byte != 0x5c) or (each_byte == 15 and in_byte != 0xf0)):
                            continue
                    if each_block == 1:
                        if ((each_byte == 0 and in_byte != 0x99) or (each_byte == 1 and in_byte != 0x7d) or (each_byte == 2 and in_byte != 0xc6) or (each_byte == 3 and in_byte != 0x4f)
                            or (each_byte == 4 and in_byte != 0xd9) or (each_byte == 5 and in_byte != 0x8e) or (each_byte == 6 and in_byte != 0xaa) or (each_byte == 7 and in_byte != 0xbd)
                            or (each_byte == 8 and in_byte != 0xae) or (each_byte == 9 and in_byte != 0x7f) or (each_byte == 10 and in_byte != 0xb7) or (each_byte == 11 and in_byte != 0x82)
                            or (each_byte == 12 and in_byte != 0xa4) or (each_byte == 13 and in_byte != 0xaa) or (each_byte == 14 and in_byte != 0x35) or (each_byte == 15 and in_byte != 0xba)):
                            continue

                    iv_prime[by_p-2:by_p or None] = f"{in_byte:02x}" #해당 위치를 0x00~0xff로 변조
                    send_msg = bytes.fromhex(''.join(iv_prime) + cipher_block) #iv_prime과 ciphertext를 연접
                    send_attack_enc_data(server, 253, send_msg, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV) #메시지 송신, 수신
                    protocol, msg_len, msg, mac = get_attack_enc_data(server, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)
                
                    print(f"\n*끝에서 {each_block + 1}번째 block의 {16 - each_byte}번째(=끝에서 {each_byte + 1}번째) byte를 {in_byte:02x}으로 변조")
                    print(f"보낸 메시지          | {send_msg.hex()}")
                    print(f"받은 메시지          | {msg.decode()}")

                    if msg.decode() == "OK+": #OK+를 받으면 후보키에 저장, 다음 byte 변조 시작 전에 복호화
                        if each_byte == 0 and len(candidate) == 0: #끝 byte의 경우 후보키가 2개일 수 있어 다른 처리 필요
                            if len(candidate) == 0:
                                candidate.append(f"{(int(''.join(iv_prime[by_p-2:by_p or None]), 16) ^ (each_byte + 1)):02x}")
                                is_1st_cand_true = 1
                                print(f"특이 사항            | 1번째 후보키를 찾았습니다!")
                                print(f"                     | 끝 byte는 후보키가 2개일 수 있어 브루트 포스를 계속 진행합니다.")
                                continue
                            else:
                                candidate.append(f"{(int(''.join(iv_prime[by_p-2:by_p or None]), 16) ^ (each_byte + 1)):02x}")
                                is_1st_cand_true = 1
                                print(f"특이 사항            | 2번째 후보키를 찾았습니다!")
                                print(f"                     | 후보키 2개를 전부 찾았으므로 복호화를 시도합니다.")
                                break
                        else: #끝 byte가 아닌 나머지의 경우 바로 복호화 시도
                            candidate.append(f"{(int(''.join(iv_prime[by_p-2:by_p or None]), 16) ^ (each_byte + 1)):02x}")
                            is_1st_cand_true = 1
                            print(f"특이 사항            | 후보키를 찾았습니다! 복호화를 시도합니다.")
                            break

    return ''.join(plaintext)



    '''''''''''''''''''''send_enc_data에서 주석, print_packet을 지우고 프로토콜만 바꾼 함수 '''''''''''''''''''''''''''
def send_attack_enc_data(soc:socket, protocol:int,msg:bytes,MAC_KEY, CIPHER_KEY, CIPHER_IV):
    data = (253).to_bytes(1, "little") + len(msg).to_bytes(4, "little") + msg
    mac = Calc_MAC(MAC_KEY, data)
    data = data + mac
    ciphertext = AES_CBC_Ecnrypt(CIPHER_KEY, CIPHER_IV, data)

    time.sleep(0.5)
    soc.sendall(ciphertext)



    '''''''''''''''''''''get_enc_data에서 주석, print_packet을 지우고 MAC, msg_len 검증 실패 시에만 문구 출력하도록 바꾼 함수 '''''''''''''''''''''''''''
def get_attack_enc_data(soc:socket,SERVER_MAC_KEY,SERVER_CIPHER_KEY,SERVER_CIPHER_IV):
    data = soc.recv(BUFFER_SIZE)
    dec_msg = AES_CBC_Decrypt(SERVER_CIPHER_KEY, SERVER_CIPHER_IV, data)
    data = dec_msg[:len(dec_msg)-16]
    mac = dec_msg[len(dec_msg)-16:]
    if Calc_MAC(SERVER_MAC_KEY, data) == mac:
        pass
    else: 
        print(f"MAC이 다릅니다.")
        exit(0)

    protocol = int.from_bytes(data[:1],"little")
    msg_len = int.from_bytes(data[1:5],"little")
    msg = data[5:]
    
    if len(msg.decode()) == msg_len:
        pass
    else:
        print(f"{len(msg.decode())}: 직접 계산한 msg_len\n{msg_len}: 복호화된 데이터에 있던 msg_len\n--> msg_len이 다릅니다.")
        exit()
    
    return (protocol, msg_len, msg, mac)



def DECRYPT_IMAGE(key):
    with open("C://Users//user//Desktop//Study//2024_secureprotocol//2024_secureprotocol//7.png", "rb") as f:
        encrypted_image = f.read()

    iv = encrypted_image[:16]
    ciphertext = encrypted_image[16:]
    decrypted = AES_CBC_Decrypt(key, iv, ciphertext)
    if decrypted[:8] == bytes.fromhex("89504e470d0a1a0a"):
        print("복호화가 잘 동작했습니다. 복호화된 파일의 헤더가 png의 헤더와 일치합니다.")
        with open("C://Users//user//Desktop//Study//2024_secureprotocol//2024_secureprotocol//decrypt_7.png", "wb") as f:
            f.write(decrypted)
        print("파일 쓰기를 완료했습니다. 결과를 확인하세요!")
    else:
        print("키가 잘못되었습니다. 복호화된 파일의 헤더가 png의 헤더와 다릅니다. 프로그램을 종료합니다.")
        exit(0)

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''



####################################################################
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
#ECHO_CLIENT START!
def ECHO_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    
    while True:
        #############################################
        # 구현필요
        # 메시지를 입력하기 (ex: msg = input("SendMsg:").encode())
        # 입력한 msg를 서버에 송신(send_enc_data 사용)
        # 서버에서 반환한 메시지를 수신 (get_enc_data 사용)
        #
        ##############################################

        msg = input("전송할 메시지: ").encode()
        send_enc_data(server, 254, msg, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV)
        
        # 만약 주고받은 메시지가 quit, QUIT, Quit 중 하나인경우 통신 종료
        protocol, msg_len, msg, mac = get_enc_data(server, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)
        if protocol == protocol_str["ECHO Mode"]:
            if (msg == b"quit") or (msg == b"QUIT") or (msg == b"Quit"):
                return


##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
####################################################################


####################################################################
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
def send_enc_data(soc:socket, protocol:int,msg:bytes,MAC_KEY, CIPHER_KEY, CIPHER_IV):
    #############################################
    # 구현필요 (send data 참고) (|| <<- 연접 기호)
    # 1. MAC값 계산용 data 생성   data = 프로토콜 || 메시지길이 || 전송하고자 하는 메시지
    # 2. data에 대한 MAC값 계산 - Calc_MAC 함수 활용(HMAC-SHA256)
    # 3. (data || MAC) 암호화    ciphertext = enc(data||mac)  - AES_CBC_Encrypt 함수 활용
    #############################################
    data = (254).to_bytes(1, "little") + len(msg).to_bytes(4, "little") + msg
    mac = Calc_MAC(MAC_KEY, data)
    data = data + mac
    ciphertext = AES_CBC_Ecnrypt(CIPHER_KEY, CIPHER_IV, data)

    time.sleep(0.5) 
    soc.sendall(ciphertext)
    
    #for debug
    print_packet("Send ->",data) 
    print_packet("Send(enc) ->",ciphertext,True)
    


def get_enc_data(soc:socket,SERVER_MAC_KEY,SERVER_CIPHER_KEY,SERVER_CIPHER_IV):
    
    data = soc.recv(BUFFER_SIZE)    
    print_packet("Get(enc) : ",data,True)
    
    #############################################
    # 구현필요    
    #  1. 데이터 복호화 - AES_CBC_Decrypt 함수 활용
    #  2. MAC 값 검증 - Calc_MAC 함수 활용(HMAC-SHA256)
    #  3. 복호화된 데이터(프로토콜 || 메시지길이 || 메시지) 파싱 
    #############################################
    dec_msg = AES_CBC_Decrypt(SERVER_CIPHER_KEY, SERVER_CIPHER_IV, data)
    data = dec_msg[:len(dec_msg)-16]
    mac = dec_msg[len(dec_msg)-16:]
    if Calc_MAC(SERVER_MAC_KEY, data) == mac:
        print(f"{Calc_MAC(SERVER_MAC_KEY, data).hex()}: 직접 계산한 MAC\n{mac.hex()}: 복호화된 데이터에 있던 MAC\n--> MAC이 검증되었습니다.")
    else: 
        print(f"{Calc_MAC(SERVER_MAC_KEY, data).hex()}: 직접 계산한 MAC\n{mac.hex()}: 복호화된 데이터에 있던 MAC\n--> MAC이 다릅니다.")
        exit(0)

    protocol = int.from_bytes(data[:1],"little")
    msg_len = int.from_bytes(data[1:5],"little")
    msg = data[5:]
    
    if len(msg.decode()) == msg_len:
        print(f"{len(msg.decode())}: 직접 계산한 msg_len\n{msg_len}: 복호화된 데이터에 있던 msg_len\n--> msg_len이 검증되었습니다.")
    else:
        print(f"{len(msg.decode())}: 직접 계산한 msg_len\n{msg_len}: 복호화된 데이터에 있던 msg_len\n--> msg_len이 다릅니다.")
        exit()
    print(f"받은 메시지 값은 {msg.decode()} 입니다.")

    return (protocol, msg_len, msg, mac)

##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
####################################################################

# 이 이하로는 주요 함수 구현 예시(그대로 사용하여도 됨)

#패킷 송신용 함수 그대로 사용 가능
def send_data(soc:socket, protocol:int,msg:bytes):
    p = protocol.to_bytes(1,"little") # int형 데이터를 byte로 변환
    msg_len = len(msg).to_bytes(4,"little") # 메시지 길이를 byte로 변환 - little endian 사용
    data = p+msg_len+msg # 패킷 데이터 : 프로토콜 || 메시지길이 || 메시지

    time.sleep(0.5)  #패킷을 너무 빠르게 전송하면 주고받기가 되지않기에 지연시간 추가
    soc.sendall(data) # 패킷 전송
    
    #for debug
    print_packet("C>",data) # 보낸 데이터 보기용
    
#패킷 수신용 함수 그대로 사용 가능
def get_data(soc:socket):
    packetsize = 5
    
    data = soc.recv(BUFFER_SIZE)
    if len(data)<=packetsize: #protocol + message_len =5 
        return False # msg가 없는경우
    
    protocol= data[0] # 프로토콜 파싱
    
    msg_len = int.from_bytes(data[1:5],"little") #메시지 길이 파싱 (byte -> int)
    packetsize +=msg_len # 패킷 길이 = protocol(1바이트) + message_len(4바이트) + 실제 메시지길이
    
    if len(data)!= packetsize: # 패킷을 비정상적으로 받은 경우
        return False 
    
    msg = data[5:5+msg_len] # 메시지 파싱
        
    #for debug
    print_packet("S<",data) # 받은 데이터 보기용
    
    return (protocol, msg_len, msg)




# 안전한 난수생성기 (num byte만큼 난수 생성)
def gen_random(num):
    import os
    return os.urandom(num)


# RSA로 암호화/ 인코딩된 인증서 넣으면 자동으로 인식
def RSA_Encrypt(pub,data):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP as RSA_OAEP
    
    publickey = RSA.import_key(pub)
    encryptor = RSA_OAEP.new(publickey)
    ciphertext = encryptor.encrypt(data)
    return ciphertext


#AES CBC모드 암호화
def AES_CBC_Ecnrypt(key:bytes,iv:bytes,data:bytes)->bytes:
    from Crypto.Cipher import AES
    if len(key) not in [16,24,32]:
        print("AES Key length error")
        exit(1)
    if len(iv) != 16:
        print("IV length error")
        exit(1)
    
    # padding
    padlen = 16-len(data)%16
    pad = bytes([padlen]*padlen)
    data = data + pad
    
    cipher = AES.new(key,AES.MODE_CBC,iv)
    return cipher.encrypt(data)   
    

#AES CBC모드 복호화
def AES_CBC_Decrypt(key:bytes,iv:bytes,data:bytes)->bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key,AES.MODE_CBC,iv)
    pt = cipher.decrypt(data)
    
    #unpadding
    padlen = pt[-1]
    if padlen>16:
        print("padding check failed 1")
        return None
    
    pad = bytes([padlen]*padlen)
    if pt[-1*padlen : ] != pad:
        print("padding check failed 2")
        return None
    return pt[:-1*padlen]



#HMAC-SHA256 계산한 결과의 상위 16바이트 반환
def Calc_MAC(mackey,data):
    hmac_obj = hmac.new(mackey,digestmod=hashlib.sha256)
    hmac_obj.update(data)
    return hmac_obj.digest()[:16]


#HKDF 함수
def HKDF(Secret, label, c_random,s_random,outlen):
    if type(label)==str:
        label= label.encode()
    ret=b""
    seed = c_random+s_random
    while len(ret)<outlen:
        hmac_obj = hmac.new(Secret, digestmod=hashlib.sha256)
        hmac_obj.update(label+seed)
        digest =hmac_obj.digest()
        seed = digest[:]
        ret+=digest
    return ret[:outlen]

    


# 이 이하로 수정 금지
def main(server:socket):
    start_mini_tls(server)
    
if __name__=='__main__':
    
    HOST = "210.123.39.41"
    PORT = 33333
    ADDRESS = (HOST,PORT)
    server = socket(AF_INET, SOCK_STREAM)
    server.connect(ADDRESS)
    server.settimeout(360)
    main(server)    
    server.close()
    

