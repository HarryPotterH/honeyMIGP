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

kb = Keyboard()
query_pre_time_list = []
server_time_list = []
total_time_list = []

username_list = [
                 ]
passwords_list = [
                  ]

# 源代码的操作   返回bytes型，长度32
def sha256bin(byte_str):
    digest = hashlib.sha256(byte_str).digest()
    return digest


# 和上一个的区别就是hexdigest返回的是string型，长度是上一个返回的2倍，64
def sha256hex(byte_str):
    hexdigest = hashlib.sha256(byte_str).hexdigest()
    return hexdigest


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

    server_time_start = time.time()
    resp = requests.post('http://123.249.27.168:8007/check/', data=data)
    server_time_end = time.time()
    server_time_list.append(server_time_end - server_time_start)
    # print("send data to c3server!")

    server_response = resp.content.decode()

    print("c3server response is:", end='')
    print(resp)

    if server_response == "no bucket":
        print("none")
    else:
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
        for pair in bucket:
            if z_0 == pair[0]:
                checked = 1
                break
        # matchnum = ''

        if checked:
            # print(index)  #此时证明客户端输入的数据的加密值在数据桶中，我们取得它的索引，下一步要把它传给honeychecker
            # matchnum = 'z_0'
            print("match")

        else:
            for pair in bucket:
                if z_1 == pair[0]:
                    checked = 1
                    break
            if checked:
                # print(index)
                # matchnum = 'z_1'
                print("similar")

        if checked == 0:
            print("none")

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

print("总响应时间：")
print("平均延迟为")
print(np.mean(total_time_list))
print("方差为")
print(np.var(total_time_list))
print("标准差为")
print(np.std(total_time_list,ddof=1))
