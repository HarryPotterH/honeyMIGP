import flask
import requests
import time
from petlib.ec import EcGroup, EcPt 
import pandas as pd
import traceback
import numpy as np  
import hashlib  
import json 
import string   
import random
import requests
from gmssl import sm3
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import binascii
from word2keypress import Keyboard
from ast import literal_eval
from hmqv import *
kb = Keyboard()  


#源代码的操作   返回bytes型，长度32
def sha256bin(byte_str):
    digest = hashlib.sha256(byte_str).digest()
    return digest  
#和上一个的区别就是hexdigest返回的是string型，长度是上一个返回的2倍，64
def sha256hex(byte_str):
    hexdigest = hashlib.sha256(byte_str).hexdigest()
    return hexdigest      
    

def locateip():#TYPE == STR
    import requests
    res = requests.get('http://123.249.9.151:8009/helloip', timeout=5).text
    return res

# client gengerates keys


G = EcGroup(714)
q = G.order()

client_key = q.random()
client_inverse_key = client_key.mod_inverse(q) 
# print(client_key) 
# print(client_inverse_key)  
username = input("please input username:")
pw = input("please input password:") 
#bucket_id = sha256hex(username.encode())[0:5] 
bucket_id = sm3.sm3_hash(list(username.encode()))[0:5]

print("bucket_id为：",end='')
print(bucket_id)

x = len(username).to_bytes(1, 'little') + username.encode() + len(pw).to_bytes(1, 'little') + pw.encode()
hash = sm3.sm3_hash(list(x)) 
hash = binascii.unhexlify(hash)
H = G.hash_to_point(hash)
pr_value = H.__rmul__(client_key)
pr_value = pr_value.__str__() 


print("pr_value is:",end='')
print(pr_value)
  

data = dict(bucket_id=bucket_id, pr_value=pr_value) 

resp = requests.post('http://123.249.27.168:8007/check/', data=data)

print("send data to c3server!")

server_response = resp.content.decode()

print("c3server response is:",end='')
print(resp)

if server_response == "no bucket":
    print("none")
else:
    client_static_private_key = 77431548113892569235645324822290678930730337342509581216943487203749942232105    
    client = HMQV(True, client_static_private_key) 

    client_static_private = client.get_static_private_key()    
    client_static_public = client.generate_static_public_key()
    client_ephemeral_private = client.get_ephemeral_private_key()  
    client_ephemeral_public = client.generate_ephemeral_public_key() 
    keysdata = dict(client_ephemeralkey=client_ephemeral_public, client_statickey=client_static_public) 
    keyresp = requests.post('http://123.249.9.151:8009/getkey/', data=keysdata)

    print("连接honeychecher获得HMQVgetkey成功,值为",end='')

    checkerkeys = json.loads(keyresp.content.decode())

    print(checkerkeys)
    
    checker_ephemeral_public = checkerkeys["checker_ephemeralkey"]
    checker_static_public = checkerkeys["checker_statickey"] 
    client_shared = client.generate_shared_key(client_ephemeral_public,checker_static_public,checker_ephemeral_public,locateip())  
    #print(client_shared)
    
    server_response = json.loads(server_response)
    bucket = server_response["bucket"]
    y = server_response["pr_value"]

    y = bytes.fromhex(y)
    y = EcPt.from_binary(y, G) 
    H_k = y.__rmul__(client_inverse_key) 
    F_k = sm3.sm3_hash(list(x + bytes.fromhex(H_k.__str__())))    
    F_k = binascii.unhexlify(F_k)
    z_0 = str(int.from_bytes(F_k, byteorder='big', signed=False) ^ 0) 
    z_1 = str(int.from_bytes(F_k, byteorder='big', signed=False) ^ 1) 

    checked = 0 #为1则加密值在数据桶中
    crypt_sm4 = CryptSM4() 
    for pair in bucket:
        if z_0 == pair[0]:
            checked = 1
            index = pair[1]  
            break
    matchnum = ''
    
    key = client_shared.encode() 
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    enc_bucket_id = crypt_sm4.crypt_ecb(bucket_id.encode()) 
    
    if checked: 
        # print(index)  #此时证明客户端输入的数据的加密值在数据桶中，我们取得它的索引，下一步要把它传给honeychecker 
        matchnum = 'z_0'
        enc_matchnum = crypt_sm4.crypt_ecb(matchnum.encode())   
        enc_index = crypt_sm4.crypt_ecb(str(index).encode())   
        data = dict(bucket_id = enc_bucket_id.hex(), index = enc_index.hex(), matchnum = enc_matchnum.hex())
        honeyresp = requests.post('http://123.249.9.151:8009/honeycheck/', data=data)

    else:
        for pair in bucket:
            if z_1 == pair[0]:
                checked = 1
                index = pair[1]  
                break
        if checked:
            # print(index)
            matchnum = 'z_1'
            enc_matchnum = crypt_sm4.crypt_ecb(matchnum.encode())   
            enc_index = crypt_sm4.crypt_ecb(str(index).encode())   
            data = dict(bucket_id = enc_bucket_id.hex(), index = enc_index.hex(), matchnum = enc_matchnum.hex())
            honeyresp = requests.post('http://123.249.9.151:8009/honeycheck/', data=data)

    if checked == 0:
        matchnum = 'none'
        enc_matchnum = crypt_sm4.crypt_ecb(matchnum.encode())
        random_index = random.randint(0,2000)
        enc_index = crypt_sm4.crypt_ecb(str(random_index).encode()) 
        data = dict(bucket_id = enc_bucket_id.hex(), index = enc_index.hex(), matchnum = enc_matchnum.hex())
        honeyresp = requests.post('http://123.249.9.151:8009/honeycheck/', data=data)

    enc_res = honeyresp.content.decode()
    crypt_sm4.set_key(key, SM4_DECRYPT)
    res = crypt_sm4.crypt_ecb(bytes.fromhex(enc_res))
    
    print(res.decode()) 


