
import pymysql
import traceback
#get 3count from database
def get_data():
    conn = pymysql.connect(
        host="127.0.0.1",
        port=3306, 
        user="root",
        password="",
        database="counter_schedule",
        charset="utf8mb4" 
        )
    cursor = conn.cursor() 
    sql = """
        select * from counter;
        """
    data = []
    try:  
        cursor.execute(sql) 
        data = list(cursor.fetchall())
        cursor.close()  
        conn.commit()  

    except Exception as e:
            # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()
    cursor.close()  
    conn.close()  
    return data
#set 3count 0
def set_zero():
    conn = pymysql.connect(
        host="127.0.0.1",
        port=3306, 
        user="root",
        password="",
        database="counter_schedule",
        charset="utf8mb4" 
        )
    cursor = conn.cursor() 
    sql = """
        UPDATE counter SET real_count =0,honeyword_count=0,other_count=0;
        """
    try:  
        cursor.execute(sql) 
        cursor.close()  
        conn.commit()  

    except Exception as e:
            # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()
    cursor.close()  
    conn.close()  
    return 0

#get data from ip_table(record ip)
def get_client_ip():
    conn = pymysql.connect(
        host="127.0.0.1",
        port=3306, 
        user="root",
        password="",
        database="visitip",
        charset="utf8mb4" 
        )
    cursor = conn.cursor() 
    sql = """
        select ip,count(type) from ip_list GROUP BY ip;
        """
    data = []
    try:  
        cursor.execute(sql) 
        data = list(cursor.fetchall())
        cursor.close()  
        conn.commit()  

    except Exception as e:
            # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()
    cursor.close()  
    conn.close()  
    return data


#when detected DOS ATTACK ,LOCK the ip,and empty the table
def drop_table():
    conn = pymysql.connect(
        host="127.0.0.1",
        port=3306, 
        user="root",
        password="",
        database="visitip",
        charset="utf8mb4" 
        )
    cursor = conn.cursor() 
    sql = """
        DROP TABLE IF EXISTS ip_list;
        """
    try:  
        cursor.execute(sql) 
        cursor.close()  
        conn.commit()  
        print("Table dropped!")
    except Exception as e:
            # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()
    cursor.close()  
    conn.close()  
def create_ip_table():
    conn = pymysql.connect(
        host="127.0.0.1",
        port=3306, 
        user="root",
        password="",
        database="visitip",
        charset="utf8mb4" 
        )
    cursor = conn.cursor() 
    sql = """
        CREATE TABLE ip_list (
  ip varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  time varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  type int NULL DEFAULT NULL
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;
        """
    try:  
        cursor.execute(sql) 
        cursor.close()  
        conn.commit()  
        print("Table created!")
    except Exception as e:
            # 有异常，回滚事务
        print('traceback.format_exc():\n%s' % traceback.format_exc())
        conn.rollback()
    cursor.close()  
    conn.close()
    
    
#initial statics by research
real = 100
honey = 200
other = 100
cycle = 10
s = (real,honey,other)
staticsdata = []


#预设定的阈值
honeyDiff1 = 10
otherDiff1 = 10

honeyDiff2=100
oterDiff2= 100
realDiff2 = 100

w = 1/19 #w为根据真实口令分布和honeyword分布设定的比例参数
#initalize staticsdata
for i in range(cycle):
    staticsdata.append(s)



import schedule
import time
 
def run():

    print("I'm doing something...")
    data = get_data()[0]
    global staticsdata#,honeyDiff1,otherDiff1,oterDiff2,realDiff2,w,cycle
    realIncrease = data[0]-sum([staticsdata[-i][0] for i in range(10)])/cycle
    honeyIncrease = data[1]-sum([staticsdata[-i][1] for i in range(10)])/cycle
    otherIncrease = data[2]-sum([staticsdata[-i][2] for i in range(10)])/cycle
    
    if honeyIncrease>honeyDiff1 and otherIncrease>otherDiff1:
        print("Dos attack!!!")
        #启动执行DoS攻击对应的安全措施,例如，屏蔽发起DoS攻击的IP
        #if one IP's visit type ceasing the limit,than lock it
        limit = 20
        lock_list = []#ip that locked
        for i in get_client_ip():
            if i[1]>limit:
                lock_list.append(i[0])
        print(lock_list)
        drop_table()
        create_ip_table()#清空记录IP的表格，重新统计
        
        
    if realIncrease>realDiff2 and honeyIncrease>honeyDiff2 and otherIncrease<oterDiff2:
        print("database leaked!!!")
        #口令文件泄漏，并启动相应的安全机制，如排查服务器漏洞、要求用户修改口令等
    if honeyIncrease-w*otherIncrease>honeyDiff2:
        print("database leaked!!!")
        #口令文件泄漏，并启动相应的安全机制，如排查服务器漏洞、要求用户修改口令等
    
    staticsdata.append(data)  #updata this period's data to staticsdata
    
    #if lent is too long ,get last 10 data
    if len(staticsdata)>10000:
        staticsdata = staticsdata[-10:]
    set_zero()
    #print(staticsdata)
    
    
schedule.every().seconds.do(run)    # 每隔2分钟执行一次任务,,now is one second

 
while True:
    schedule.run_pending()  # run_pending：运行所有可以运行的任务


