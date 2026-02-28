from Crypto.Cipher import AES
import base64

#pref_database_encrypted_secret에서 가져온 data와 iv
encoded_data = "ze7wmwGfvFx15KBUc/4gNQM582R7SIowkJM9h2e5d2qUDZdRwxklx8xyljyRLTH/"
encoded_iv = "D3DRepyI1KsXAuHO"

#persitent.sqlite에서 가져온 key
android_keystore_key = bytes([0x79, 0xfa, 0x7c, 0x4a, 0x90, 0xa5, 0x53, 0x95, 0xb1, 0x1a, 0x2b, 0x49, 0x7a, 0x82, 0x57, 0x8d])
#base64로 디코딩을 해준다
decoded_data = base64.b64decode(encoded_data.encode())
decoded_iv = base64.b64decode(encoded_iv.encode())

#encrypted key랑 tag 추출
encrypted_key = decoded_data[:32]
tag = decoded_data[-16:]

#GCM모드 복호화해주기
cipher = AES.new(android_keystore_key, AES.MODE_GCM, nonce=decoded_iv)

#검색해보니 GCM에서는 decrypt_and_verify()라는것으로 복호화와 인증 태그를 검증해야한다고 함
passphrase = cipher.decrypt_and_verify(encrypted_key, tag)

print("Decrypted passphrase : ", passphrase.hex())



