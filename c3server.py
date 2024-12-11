import flask
import requests
import time
from petlib.ec import EcGroup, EcPt 
import pandas as pd
import traceback
import numpy as np 
import hashlib  
import json 
import pymysql
import string   
import random
from word2keypress import Keyboard
from ast import literal_eval
kb = Keyboard() 
import flask
from flask import request
#源代码的操作   返回bytes型，长度32
def sha256bin(byte_str):
    digest = hashlib.sha256(byte_str).digest()
    return digest
#和上一个的区别就是hexdigest返回的是string型，长度是上一个返回的2倍，64
def sha256hex(byte_str):
    hexdigest = hashlib.sha256(byte_str).hexdigest()
    return hexdigest

#取出server_key
from petlib import bn
bntype = bn.Bn()
server_key = bntype.from_decimal("106359593625878955332025896546857009298373614676778833330321731091181100479634")

def getbucket(bucket_id):
    conn = pymysql.connect(
    host="localhost",
    port=3306, 
    user="root",
    password="f32f8491123f20f2",
    database="c3server_v3",
    charset="utf8mb4" 
    )
    cursor = conn.cursor() 
    sql = """
    select * from bucket_{}
    """.format(bucket_id) 
    try:  
        cursor.execute(sql) 
        data = list(cursor.fetchall())
        cursor.close()  
        conn.commit()  
        conn.close()  
        return data 
    except Exception as e:
        # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback() 
        if "1146" in traceback.format_exc():
        	return "no bucket"
    cursor.close()  
    conn.close()     

app = flask.Flask(__name__) 
@app.route('/check/', methods=['GET', 'POST'])
def server_check():
    response_message = {}
    pr_value = request.form['pr_value']
    bucket_id = request.form['bucket_id']
    print(f'=============\npr_value = {pr_value}; bucket_id = {bucket_id}=========\n')
    G = EcGroup(714)
    bucket = getbucket(bucket_id) 
    if bucket == "no bucket":
    	response_message = "no bucket"
    	return response_message
    val = EcPt.from_binary(bytes.fromhex(pr_value), G) 
    y = val.__rmul__(server_key) 
    y = y.__str__()
    
    response_message = dict(bucket = bucket, pr_value = y)
    #print(f'process request time = {time.time() - stat}')
    return response_message 

@app.route('/', methods=['GET', 'POST'])
def helloip():
    return request.remote_addr

if __name__ == "__main__":
    ''' Running the server '''
    app.run(host='0.0.0.0',port='8007',  debug=True)
