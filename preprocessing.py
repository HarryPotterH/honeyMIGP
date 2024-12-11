from petlib.ec import EcGroup, EcPt  
import pymysql
import pandas as pd
import traceback
import numpy as np 
import hashlib  
import json
import time
import string  
import random
from word2keypress import Keyboard
from ast import literal_eval
import binascii
kb = Keyboard()  
def get_random_string(size): 
    random_number = [random.choice(string.ascii_letters + string.digits) for n in range(size)] # 32 bytes
    return "".join(random_number)     


# load the transformation rules and their count
with open('transition_count_1.json') as f:
    count = json.load(f)
count_sort_1 = sorted(count.items(), key=lambda kv: kv[1], reverse = True)

with open('transition_count_2.json') as f:
    count = json.load(f)
count_sort_2 = sorted(count.items(), key=lambda kv: kv[1], reverse = True)

with open('transition_count_3.json') as f:
    count = json.load(f) 

# take top 200 from paths of length 1,2 and 3 and sort them based on count
count_sort_3 = sorted(count.items(), key=lambda kv: kv[1], reverse = True)

temp_cs = count_sort_1[:200] + count_sort_2[:200] + count_sort_3[:200]
temp_cs_sort = sorted(temp_cs, key=lambda kv: kv[1], reverse = True)
rules_list = temp_cs_sort 


def edit_distance(str1, str2):
    # Transform to keyboard representation:
    kb = Keyboard()
    str1 = kb.word_to_keyseq(str1)
    str2 = kb.word_to_keyseq(str2)
    # Definitions:
    n = len(str1) 
    m = len(str2)
    D = np.full((n + 1, m + 1), np.inf)
    # Initialization:
    for i in range(n + 1):
        D[i,0] = i
    for j in range(m + 1):
        D[0,j] = j
    # Fill the matrices:
    for i in range(1, n + 1):
        for j in range(1, m + 1): 
            delete = D[i - 1, j] + 1
            insert = D[i, j - 1] + 1
            if (str1[i - 1] == str2[j - 1]):
                #字符相同则是copy操作
                sub = np.inf
                copy = D[i - 1, j - 1]
            else:
                #字符不同是substitute操作
                sub = D[i - 1, j - 1] + 1
                copy = np.inf
            op_arr = [delete, insert, copy, sub]
            D[i ,j] = np.min(op_arr)
    return D[n ,m]


def _apply_edits(wordkeyseq, path):
    """A slightly faster variant of path2word_kb_feasible. Good to be used from tweaking_rules.
    @wordkeypress: key-press representation of the word
    @path: an array of edits
    """
    word = wordkeyseq
    if not path:
        return kb.keyseq_to_word(word)
    final_word = []
    word_len, path_len = len(word), len(path)
    i, j = 0, 0
    while (i < word_len or j < path_len):
        if ((j < path_len and path[j][2] == i) or (i >= word_len and path[j][2] >= i)):
            if (path[j][0] == "s"):
                # substitute
                final_word.append(path[j][1])
                i += 1
                j += 1
            elif (path[j][0] == "d"):
                # delete
                i += 1
                j += 1
            else:
                # "i", insert
                final_word.append(path[j][1])
                j += 1
        else:
            if (i < word_len):
                final_word.append(word[i])
                i += 1
            if (j < path_len and i > path[j][2]):
                j += 1
    return kb.keyseq_to_word(''.join(final_word))

# function to get n tweaks for a word
P_LIST = []
def get_tweaks_rules(word, K, BL=[]):

    tweaks = set()
    global P_LIST
    if not P_LIST:
        for pathstr, f in rules_list:
            edits = pathstr.split('+')
            path_list = []
            for e in edits:
                path = literal_eval(e)
                if path[2]<0:
                    path = (path[0], path[1], path[2]+(len(word)+1))
                path_list.append(path)
            P_LIST.append(path_list)
            if len(P_LIST) > 10 * K:
                #print(f"P_LIST size {len(P_LIST)}")
                break
    MAX_TWEAKS = K
    wordkeyseq = kb.word_to_keyseq(word)
    for p in P_LIST:
        tw = _apply_edits(wordkeyseq, p)
        if tw != word and tw not in BL:
            tweaks.add(tw)
        if len(tweaks) >= MAX_TWEAKS:
            break
    #assert len(list(tweaks)) == MAX_TWEAKS, f'Can not generate {MAX_TWEAKS}; generated {len(list(tweaks))}'
    while len(list(tweaks)) < MAX_TWEAKS:
        randomstring = get_random_string(6)
        if ramdomstring not in BL:
            tweaks.add(randomstring)
    return list(tweaks)

#源代码的操作   返回bytes型，长度32
def sha256bin(byte_str):
    digest = hashlib.sha256(byte_str).digest()
    return digest 
#和上一个的区别就是hexdigest返回的是string型，长度是上一个返回的2倍，64
def sha256hex(byte_str):
    hexdigest = hashlib.sha256(byte_str).hexdigest()
    return hexdigest 

from gmssl import sm3
import binascii


#生成block_list
fin = open("BlockList10000.txt",'r', encoding="UTF-8") 
line = fin.readline().replace("\n","") 
block_list = [] 
while line:
    password = line
    line = fin.readline().replace("\n","")    
    block_list.append(password)
fin.close()  


#先生成password_list
fin = open("d10000.txt",'r', encoding="UTF-8") 
line = fin.readline().replace("\n","") 
passwords_list = [] 
start = time.time()
while line:
    password = line.split(" : ")[1]
    line = fin.readline().replace("\n","")  
    if password not in block_list:
        passwords_list.append(password)
end = time.time() 
print(end - start)  
fin.close()


G = EcGroup(714) 
q = G.order()
from petlib import bn
bntype = bn.Bn()
server_key = bntype.from_decimal("106359593625878955332025896546857009298373614676778833330321731091181100479634")
print(server_key)
print(type(server_key))  


#创数据桶,index自动递增（从1开始）,桶的命名前面要加bucket_
def create_bucket(bucket_id):
    conn = pymysql.connect(
        host="123.249.27.168",
        port=3306,
        user="root", 
        password="",
        database="c3server_V3",
        charset="utf8mb4"
    )
    cursor = conn.cursor() 
#     bucket = "bucket_"
#     bucket += bucket_id
    sql = """
    create table if not exists bucket_{}(
        enc_credentials varchar(78) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
        server_index int AUTO_INCREMENT,         
        PRIMARY KEY (`server_index`) USING BTREE
    )ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;
    """.format(bucket_id) 
    try:  
        cursor.execute(sql)
        conn.commit()
    except Exception as e:
        # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc()) 
        conn.rollback()
    cursor.close() 
    conn.close()  

#原始操作里需要判断bucket_id是否存在,若存在，返回true，否则flase  代码是网上找的,它是检查所有数据表
def checkBucketExists(bucket_id):
    conn = pymysql.connect(
        host="123.249.27.168",
        port=3306,
        user="root", 
        password="",
        database="c3server_V3",
        charset="utf8mb4"
    ) 
    cursor = conn.cursor() 
    sql = """
        describe bucket_{} 
        """.format(bucket_id)
    try:  
        cursor.execute(sql) 
        if cursor.fetchone() != '':
            cursor.close()  
            conn.close()  
            return True    
        else:
            cursor.close()  
            conn.close()  
            return False  
    except Exception as e:
        # 有异常，回滚事务
#         print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback() 
        cursor.close()   
        conn.close()   
        return False 


#找到对应表最大id号,其实这里直接统计了table的行数
def checkMaxId(bucket_id):
    conn = pymysql.connect(
        host="123.249.27.168",
        port=3306,
        user="root", 
        password="",
        database="c3server_V3",
        charset="utf8mb4"
    )
    cursor = conn.cursor() 
    bucket = "bucket_"
    bucket += bucket_id
    sql = """
        SELECT COUNT(*)
        FROM {} 
        """.format(bucket)
    try:
        cursor.execute(sql) 
        res = cursor.fetchone()[0] 
        return res 
        conn.commit() 
    except Exception as e:
        # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()   

#向数据桶中加入加密数据,用到了executemany函数，只需插入enc_credentials
def insert_credentials(bucket_id, inserteddata):
    conn = pymysql.connect(
        host="123.249.27.168",
        port=3306,
        user="root", 
        password="",
        database="c3server_V3",
        charset="utf8mb4"
    ) 
    cursor = conn.cursor()
    bucket = "bucket_"
    bucket += bucket_id
    sql = """ 
    insert into  
    {}(enc_credentials)
    values(%s);
    """.format(bucket) 
    try: 
        cursor.executemany(sql, inserteddata)  #executemany效率快
        conn.commit() 
    except Exception as e:
        # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()
    cursor.close()  
    conn.close()    

#初始化honeychecker，给出username 和 对应的类型列表（如果不做改变就是一个固定的结果 [1,0,...,0...111]真口令1，honeyword共19个0，又100个变体为1
def create_honeychecker(bucket_id, inserteddata):
    conn = pymysql.connect(
        host="localhost",
        port=3306,
        user="root",
        password="",
        database="honeychecker_V3",
        charset="utf8mb4"
    )
    cursor = conn.cursor()
    #如果不存在，则创建表
    sql = """
    CREATE TABLE IF NOT EXISTS bucket_{} (
  `server_index` int NOT NULL COMMENT '//索引',
  `type` int NULL DEFAULT NULL COMMENT '//1表示正确pwd,0为real pw的变体',
  PRIMARY KEY (`server_index`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = DYNAMIC;
   """.format(bucket_id)
    try:  
        cursor.execute(sql) 
#         print("get it")
        conn.commit()
    except Exception as e:
        # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()
        
    #如果存在，则插入
    sql = """
    insert into bucket_{}(server_index,type) 
    values(%s,%s)
    """.format(bucket_id)
    try:
        cursor.executemany(sql, inserteddata) 
#         print("success")
        conn.commit()
    except Exception as e:
        # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc()) 
        conn.rollback()
    
    cursor.close() 
    conn.close()   




#预处理核心代码
fin = open("d10000.txt",'r', encoding="UTF-8") 
line = fin.readline().replace("\n","") 
count = 0
start = time.time()
while line: 
    count += 1
    username = line.split(" : ")[0] 
    password = line.split(" : ")[1]  #password是最原始的口令，是一切罪恶的开端
    if password in block_list:
        line = fin.readline().replace("\n","")
        continue
    real_and_similar = [] 
    totalwords = []
    #先生成19个honeywords,后续考虑honeywords的过滤问题
    sweetlist = [] 
    sweetlist.append(password)
    while len(sweetlist) < 20:
        honeyword = random.choice(passwords_list)
        flag = 1
        if honeyword not in sweetlist and honeyword not in block_list:
            for mysweet in sweetlist:
                if edit_distance(mysweet, honeyword) <= 3:
                    flag = 0
                    break
            if flag:
                sweetlist.append(honeyword) 
            
    #20个sweetwords每个生成100个变体，totalwords存放所有2020个口令，real_and_similar存放真实口令以及它的100个变体，一共101个
    for pw in sweetlist: 
        totalwords.append(pw) 
        similarwords = get_tweaks_rules(pw, 100) 
        totalwords.extend(similarwords)  
        if pw == password:
            real_and_similar.append(pw)
            real_and_similar.extend(similarwords) 
    totalwords = list(set(totalwords))  #去重，set无序,但顺序变化不大，还得用shuffle
    while len(totalwords) < 2020:  
        totalwords.append(get_random_string(6))         
    #打乱顺序
    random.shuffle(totalwords)    
    
    enc_credentials = []   #存放2020个口令加密后的数据   
    #bucket_id = sha256hex(username.encode())[0:5]
    bucket_id = sm3.sm3_hash(list(username.encode()))[0:5]
    
    for pw in totalwords:
        x = len(username).to_bytes(1, 'little') + username.encode() + len(pw).to_bytes(1, 'little') + pw.encode()
        hash = sm3.sm3_hash(list(x)) 
        hash = binascii.unhexlify(hash)
        H = G.hash_to_point(hash)
        H_k = H.__rmul__(server_key)
        pr_value = sm3.sm3_hash(list(x + bytes.fromhex(H_k.__str__()))) 
        pr_value = binascii.unhexlify(pr_value)
        if pw == password:
            pr_value = int.from_bytes(pr_value, byteorder='big', signed=False) ^ 0
        else:
            pr_value = int.from_bytes(pr_value, byteorder='big', signed=False) ^ 1
        enc_credentials.append(str(pr_value))
            
    
    checkerindexes = [] 
    typelist = []
    if checkBucketExists(bucket_id):  #若桶存在
        maxid = int(checkMaxId(bucket_id))
        insert_credentials(bucket_id, enc_credentials) #insert
        
        for indexword in real_and_similar:
            if indexword == password:
                typelist.append(1)
                checkerindexes.append(maxid + totalwords.index(indexword) + 1)
            else:   
                typelist.append(0)
                checkerindexes.append(maxid + totalwords.index(indexword) + 1)
                
    else:
        create_bucket(bucket_id)
        insert_credentials(bucket_id, enc_credentials) #insert
        
        for indexword in real_and_similar:
            if indexword == password:
                typelist.append(1)
                checkerindexes.append(totalwords.index(indexword) + 1)
            else:   
                typelist.append(0)
                checkerindexes.append(totalwords.index(indexword) + 1)
                
    inserteddata = list(zip(checkerindexes, typelist)) 
    create_honeychecker(bucket_id, inserteddata)
        
    if count % 100 == 0:
        print("{} have been done".format(count))
#         mid = time.time() 
#         print(mid - start)  
    line = fin.readline().replace("\n","") 
end = time.time()    
print(end - start)    








