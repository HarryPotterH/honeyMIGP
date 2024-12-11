>  honeyMIGP:口令泄露查询系统的设计与实现
>
>

代码结构介绍：
- preprocessing.py为数据预处理代码
- client.py为客户端本地运行的源代码
- c3server.py为c3服务器的源代码
- honeychecker.py为honeychecker服务器的原代码
- hmqv.py为client.py和honeychecker.py用的头文件，其内容包含hmqv的实现
- monitorf.py为监控程序的源代码，用于判断服务器是否遭受DoS攻击或者数据库文件是否泄露，并进行相应的保护措施

- 测试代码文件夹中包含性能测试的代码，其中test_client.py是honeyMIGP的测试，test_client_ori.py是MIGP原始测试，train.py为口令路径训练的代码
