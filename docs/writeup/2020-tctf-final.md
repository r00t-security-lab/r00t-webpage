---
sidebar: auto
---
# 2020 TCTF 决赛

决赛一堆pwn题，走了

## unlimited

题目附件`output.txt`为纯文本文件，目测其结构为某编程语言的语法分析树。从文件中提取关键词在GitHub上搜索可知，文件内容为某PHP源代码的AST，生成工具为[PHP-Parser](https://github.com/nikic/PHP-Parser)。该工具的文档中并没有提及将生成的纯文本语法树还原为PHP代码的功能，但描述了[将结构类似的JSON文本还原为PHP代码的功能](https://github.com/nikic/PHP-Parser/blob/master/doc/component/JSON_representation.markdown)。

为了将纯文本转换为合法的JSON文本，对其进行了若干处理步骤：

1. 将原始文本中的字符串常量用双引号括起；
	- 正则表达式形如：`name: (\w+)` => `name: "\1"`
2. 使用行号标记相匹配的括号，便于后续正则表达式处理（`array(%13 ... )%13`）；
	- 使用脚本依次读取每一行进行处理
3. 将`array( ... )`结构替换为Javascript格式的`[ ... ]`，并移除其中的纯数字键名；
	- 正则表达式：`array\(%(\d+)(.+)\)%\1\n` => `[\2]\n`；`^(\s+)\d+: ` => `\1`
4. 将`Class_Name( ... )`结构替换为Javascript对象`{ nodeType: "Class_Name", ... }`；
	- 正则表达式：`([ ]+)(\w+:\s)(\w+)\(%(\d+)(.+)\)%\4\n` => `\1\2{\n\1    nodeType: "\3"\5}\n`
5. 补齐缺少的逗号；
	- 正则表达式：`([^\(\[{])$` => `\1,`
6. 至此，我们得到了一个符合Javascript语法的对象字面量。使用`JSON.stringify()`函数导出JSON文本。

将JSON文本交由PHP-Parser解析（需要对其进行patch以绕过对缺少成员的检查），得到PHP代码：

```php
<?php

$f1 = function ($lII1lI1IlI) {
    return function ($II1IlllI11) use($lII1lI1IlI) {
        return function ($ll1IlllIIl) use($II1IlllI11, $lII1lI1IlI) {
            return $II1IlllI11($lII1lI1IlI($II1IlllI11)($ll1IlllIIl));
        };
    };
};

// ...
```

尝试运行之，PHP报告运行内存不足，无法继续执行。取消PHP的运行内存限制，又会因为操作系统的内存限制导致PHP进程崩溃。无奈，对被混淆的变量名进行简单的去混淆处理，开始静态分析。

该PHP程序应用类似函数式编程的概念，对函数本身进行大量（循环控制常数之一是0x18000000000000）的传递、计算、嵌套操作。再加上题目描述中提到的"unlimited memory and unlimited time"，猜测该程序执行的递归次数远远超过计算机的处理能力，需要对算法进行化简。

分析可知，程序的主要运算逻辑由加法和乘法构成，但运算操作的是函数的迭代次数而非数字：

```php
<?php

// `f_n(f)(x)` 和 `f^n(x)` （迭代`f(x)`共`n`次）等价

// f^0(x)
$f_0 = function ($f) {
    return function ($x) {
        return $x;
    };
};

// f^1(x)
$f_1 = function ($f) {
    return function ($x) use ($f) {
        return $f($x);
    };
};

// 输入：代表迭代层数`n`的函数`f_n`
// 输出：代表迭代层数`n + 1`的函数`f_{n+1}`
$f_inc = function ($n) {
    return function ($f) use ($n) {
        return function ($x) use ($f, $n) {
            return $f($n($f)($x));
        };
    };
};

// ...
```

由此，将程序中的常量表和主要运算逻辑转换为对数字进行操作，进行化简和重排，得到Python代码：

```python
m1 = [
    [8, 9, 9, 4, 0, 8, 9, 5, 3],
    [8, 0, 3, 8, 0, 5, 9, 9, 8],
    [3, 2, 0, 8, 2, 6, 0, 1, 9],
    [9, 7, 3, 2, 1, 0, 5, 9, 9],
    [8, 8, 9, 4, 0, 3, 5, 1, 5],
    [2, 9, 2, 0, 9, 7, 5, 0, 8],
    [0, 3, 7, 4, 0, 9, 0, 8, 2],
    [2, 8, 1, 3, 3, 8, 0, 7, 8]
]

m2 = m1[0].copy()

i = 0

while 0x3b800001 + i < 0x18000000000000 - i:
    m4 = m1[pow(3, i, 7)].copy()
    m5 = [0] * 9
    
    m5[0] = m2[0] * m4[0]
    m5[0] += m2[1] * m4[3]
    m5[0] += m2[2] * m4[6]
    
    m5[1] = m2[1] * m4[4]
    m5[1] += m2[0] * m4[1]
    m5[1] += m2[2] * m4[7]
    
	# ...
```

至此解决了算法运行的内存要求，但巨大的循环控制常数意味着时间要求依然没有得到解决。观察上述算法发现，循环中的算法本质上是3x3矩阵乘法，且循环本身为一个累乘过程，初始矩阵为`m1[0]`，累乘上去的矩阵依次为`m1[1]`、`m1[3]`、`m1[2]`、`m1[6]`、`m1[4]`、`m1[5]`（循环）。这意味着最终结果为上述各矩阵的若干次幂的乘积。使用快速幂算法进行计算，得到flag：

```C

const int N = 3;
long long mod = 1000000007;
long long temp[N][N],o[N][N];
long long res[N][N], a[N][N];
long long NN = 562949870234282;
//long long NN = 3;
void mul(long long c[][N], long long b[][N])//矩阵乘法 b*c -> c
{
    memset(temp, 0, sizeof(temp));
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            for (int k = 0; k < N; k++)
                temp[i][j] = (temp[i][j] + c[i][k] * b[k][j] % mod) % mod;
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            c[i][j] = temp[i][j];
    return;
}
void fun(long long nn)//快速幂，只不过底数换成了矩阵 a->res
{
    memset(res, 0, sizeof(res));
    for (int i = 0; i < N; i++)
        res[i][i] = 1;//单位阵
    while (nn) {
        if (nn & 1)//奇数的话res×a
            mul(res, a);
        mul(a, a);//a自己平方
        nn >>= 1;//幂次/2
    }
    return;
}
long long ori[8][N][N] = {{8, 9, 9, 4, 0, 8, 9, 5, 3}, 
    {8, 0, 3, 8, 0, 5, 9, 9, 8},
    {3, 2, 0, 8, 2, 6, 0, 1, 9},
    {9, 7, 3, 2, 1, 0, 5, 9, 9},
    {8, 8, 9, 4, 0, 3, 5, 1, 5},
    {2, 9, 2, 0, 9, 7, 5, 0, 8},
    {0, 3, 7, 4, 0, 9, 0, 8, 2},
    {2, 8, 1, 3, 3, 8, 0, 7, 8}};
void dump(long long c[][N]) {
    long long* p = (long long *)c;
    printf("flag{%lld-%lld-%lld-%lld-%lld-%lld-%lld-%lld-%lld}\n", p[8], p[7], p[6], p[5], p[4], p[3], p[2], p[1], p[0]);
}

int main() {//0((132645)^m)132645
    memcpy(o, ori[0], sizeof(o));

    memcpy(a, ori[1], sizeof(a));//计算132645各行矩阵的乘积
    mul(a, ori[3]);
    mul(a, ori[2]);
    mul(a, ori[6]);
    mul(a, ori[4]);
    mul(a, ori[5]);

    fun(NN);//=循环次数/6

    mul(o, res);

    dump(o); mul(o, ori[1]);
    dump(o); mul(o, ori[3]);
    dump(o); mul(o, ori[2]);
    dump(o); mul(o, ori[6]);
    dump(o); mul(o, ori[4]);
    dump(o); mul(o, ori[5]);
    dump(o);

    return 0;
}
```
结果为以下七个flag其中一个
> flag{267452128-536739207-238999148-620740750-579829093-798519321-682295668-133868279-249967397}

> flag{540310468-407069138-612975936-260629358-586666715-613453950-877608888-140660970-211346357}

> flag{701721978-560694839-32473977-186026044-226508538-997565721-532519007-518565398-571483551}

> flag{679666773-888059603-582980615-33285603-634174548-804765439-904063402-712616891-862973802}

> flag{432734187-186275980-552238391-407500134-680581127-536698178-262495339-821428559-850467550}

> flag{692644345-850641287-326681934-909527597-701085530-53410539-430970245-66235690-401931254}

> flag{149007553-595908919-116585565-290640480-790464579-654459035-715274270-213502468-958713719}


## mef

首先观察给出的python代码，进行了一个巨大的循环，循环里面还有一个遍历列表的listhash函数，理论时间复杂度将达到O(N^2)并且N非常大，因此尝试简化逻辑。
尝试使用不同列表调用listhash函数，结果均为0，观察代码
```python
def listhash(l):
    fmt = "{} "*len(l)
    s = fmt.format(*l)
    return reduce(lambda x,y:x*y,map(hash,s.split(' ')))
```
此函数首先将整个列表转换为元素+空格的字符串；然后按照空格分割；生成的字符串最后一个字符是空格，这导致分割后的列表最后会有一个空字符串；空字符串的hash结果是0，所以将hash结果相乘会是零。

那么简化题目代码：
```python
num = 0x142857142857142857
x = 1
for i in range(num):
    x = ( x*p + 1) % m
```
对于这个num，O(N)复杂度依然是不可接受的。

因为算式中仅包含加和乘，将取模运算提出最后计算，此时 x\[i\]=(x\[i-1\]*p+1)，观察x生成的过程，最开始是1然后逐渐乘p再加1，这个过程可以理解为对p进制数的按位计算，左移1再加1，从这个角度，x最后将会是一个num位的p进制数，每个位都是1。

按照进制的定义将x再拆开，会变成 1*p^num + 1*p^(num-1) + ... + p + 1,这变成了等比数列求和的样式，所以题目实际变成了等比数列求和取模(复杂度log^2n)。网上搜一段只能处理long long的等比数列求和取模程序，改为python，计算出flag。
```python
def T(n):
	if(n<=1):return 1
	tn2 = T(n//2)
	if(n&1):
		return (tn2+pow(p,n//2,m)*tn2 + pow(p,n-1,m))%m
	else:
		return (tn2+pow(p,n//2,m)*tn2)%m
	
p = 374144419156711147060143317175368453031918731002211
m = 16077898348258654514826613220527141251832530996721392570130087971041029999399
bytes.fromhex(hex(enc_flag^T(0x142857142857142857+1))[2:]).decode('ascii')
'flag{not_(mem)_hard_at_alllll}'
```

