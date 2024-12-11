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
from hmqv_new import *

kb = Keyboard()

username_list = ["00010202002102201@jhouh.com","0007.oza@mail.ru","007taz@bellsouth.com",
                 "0102469m@student.gla.ac.uk","013693@gmail.com","01hunter122@mail.ru",
                 "02rita02@excite.com","04SUS1980@mail.ru","070383af@mail.ru",
                 "07091990@homemail.com","071e3g_k6pjd14l@pochta.ru","073eustacebotellio1986251@rambler.ru",
                 "08.nova@live.fr","0810@dasd12363.com","082106331@sxmail.de",
                 "08lobach@rambler.ru","092483@snakebite.com","093tp@yandex.ru",
                 "09bpf@williams.edu","09liliya031@rambler.ru","0VV22L@126.com",
                 "594515032@qq.com","5magam5@yandex.ru","605650062@tianya.cn","LEATHAANUM@YAHOO.NO"
                 ]
passwords_list = ["footy1","sadela","clemson24",
                  "p131sus","2505Vika","1993gavr",
                  "lanceton02","WER97979797","9273469111",
                  "hardyboys1990","8x1KDv3sZ","ezmriuE1",
                  "zeqohuby","l639955","ansitanq12",
                  "201020111654op","idgoldenproperties","tuchkoFf83",
                  "griffey69", "nfnfhcrbq", "0VV22L",
                  "q594515032", "shokolad5", "lq19910629", "lars3r1"
                  ]
# 源代码的操作   返回bytes型，长度32
def sha256bin(byte_str):
    digest = hashlib.sha256(byte_str).digest()
    return digest


# 和上一个的区别就是hexdigest返回的是string型，长度是上一个返回的2倍，64
def sha256hex(byte_str):
    hexdigest = hashlib.sha256(byte_str).hexdigest()
    return hexdigest


def locateip():  # TYPE == STR
    import requests
    res = requests.get('http://123.249.9.151:8009/helloip', timeout=5).text
    return res


# client gengerates keys

query_pre_time_list = []
server_time_list = []
HMQV_time_list = []
checker_time_list = []
total_time_list = []


G = EcGroup(714)
q = G.order()

client_key = q.random()
client_inverse_key = client_key.mod_inverse(q)
# print(client_key)
# print(client_inverse_key)
for i in range(25):
    username = username_list[i]
    pw = passwords_list[i]
    total_starttime = time.time()
    # bucket_id = sha256hex(username.encode())[0:5]
    bucket_id = sm3.sm3_hash(list(username.encode()))[0:5]

    # print("bucket_id为：", end='')
    # print(bucket_id)

    x = len(username).to_bytes(1, 'little') + username.encode() + len(pw).to_bytes(1, 'little') + pw.encode()
    hash = sm3.sm3_hash(list(x))
    hash = binascii.unhexlify(hash)
    H = G.hash_to_point(hash)
    pr_value = H.__rmul__(client_key)
    pr_value = pr_value.__str__()

    # print("pr_value is:", end='')
    # print(pr_value)

    data = dict(bucket_id=bucket_id, pr_value=pr_value)

    query_pre_end = time.time()
    # query_pre_time =
    query_pre_time_list.append(query_pre_end - total_starttime)

    ##和服务器交互
    server_time_start = time.time()
    resp = requests.post('http://123.249.27.168:8007/check/', data=data)
    server_time_end = time.time()
    server_time_list.append(server_time_end - server_time_start)
    # print("send data to c3server!")

    server_response = resp.content.decode()

    # print("c3server response is:", end='')
    # print(resp)

    if server_response == "no bucket":
        print("none")
        print("\n")
        print("服务器端无桶时：")
    else:

        # HMQV生成密钥
        HMQV_start = time.time()
        client_static_private_key = 77431548113892569235645324822290678930730337342509581216943487203749942232105
        client = HMQV(True, client_static_private_key)

        client_static_private = client.get_static_private_key()
        client_static_public = client.generate_static_public_key()
        client_ephemeral_private = client.get_ephemeral_private_key()
        client_ephemeral_public = client.generate_ephemeral_public_key()
        keysdata = dict(client_ephemeralkey=client_ephemeral_public, client_statickey=client_static_public)
        keyresp = requests.post('http://123.249.9.151:8009/getkey/', data=keysdata)

        # print("连接honeychecher获得HMQVgetkey成功,值为", end='')

        checkerkeys = json.loads(keyresp.content.decode())

        # print(checkerkeys)

        checker_ephemeral_public = checkerkeys["checker_ephemeralkey"]
        checker_static_public = checkerkeys["checker_statickey"]
        client_shared = client.generate_shared_key(client_ephemeral_public, checker_static_public,
                                                   checker_ephemeral_public,
                                                   locateip())
        # print(client_shared)
        HMQV_end = time.time()
        HMQV_time_list.append(HMQV_end - HMQV_start)

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

        checked = 0  # 为1则加密值在数据桶中
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
            data = dict(bucket_id=enc_bucket_id.hex(), index=enc_index.hex(), matchnum=enc_matchnum.hex())

            checker_start = time.time()
            honeyresp = requests.post('http://123.249.9.151:8009/honeycheck/', data=data)
            checker_end = time.time()
            checker_time_list.append(checker_end - checker_start)

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
                data = dict(bucket_id=enc_bucket_id.hex(), index=enc_index.hex(), matchnum=enc_matchnum.hex())
                checker_start = time.time()
                honeyresp = requests.post('http://123.249.9.151:8009/honeycheck/', data=data)
                checker_end = time.time()
                checker_time_list.append(checker_end - checker_start)

        if checked == 0:
            matchnum = 'none'
            enc_matchnum = crypt_sm4.crypt_ecb(matchnum.encode())
            random_index = random.randint(0, 2000)
            enc_index = crypt_sm4.crypt_ecb(str(random_index).encode())
            data = dict(bucket_id=enc_bucket_id.hex(), index=enc_index.hex(), matchnum=enc_matchnum.hex())
            checker_start = time.time()
            honeyresp = requests.post('http://123.249.9.151:8009/honeycheck/', data=data)
            checker_end = time.time()
            checker_time_list.append(checker_end - checker_start)

        enc_res = honeyresp.content.decode()
        crypt_sm4.set_key(key, SM4_DECRYPT)
        res = crypt_sm4.crypt_ecb(bytes.fromhex(enc_res))

        print(res.decode())

    total_endtime = time.time()
    print(total_endtime - total_starttime)
    total_time_list.append(total_endtime - total_starttime)

print("预准备：")
print("平均延迟为")
print(np.mean(query_pre_time_list))
print("方差为")
print(np.var(query_pre_time_list))
print("标准差为")
print(np.std(query_pre_time_list,ddof=1))
print("\n")

print("服务器延迟：")
print("平均延迟为")
print(np.mean(server_time_list))
print("方差为")
print(np.var(server_time_list))
print("标准差为")
print(np.std(server_time_list,ddof=1))
print("\n")

print("HMQV：")
print("平均延迟为")
print(np.mean(HMQV_time_list))
print("方差为")
print(np.var(HMQV_time_list))
print("标准差为")
print(np.std(HMQV_time_list,ddof=1))
print("\n")

print("honeychecker检查：")
print("平均延迟为")
print(np.mean(checker_time_list))
print("方差为")
print(np.var(checker_time_list))
print("标准差为")
print(np.std(checker_time_list,ddof=1))
print("\n")

print("总响应时间：")
print("平均延迟为")
print(np.mean(total_time_list))
print("方差为")
print(np.var(total_time_list))
print("标准差为")
print(np.std(total_time_list,ddof=1))