---
title: security summary
date: 2017-10-24 15:18:57
categories:
- 网络安全
tags:
- ECC
- RSA
- SHA
---

# 写在前面
近期将接手一个ECC（Elliptic Curve Cryptosystem，椭圆曲线密码系统）方面的开发工作。从未接触过数据加解密相关的知识，于是查阅了一些文档，在此记录一下自己的理解。
理解应有偏差，后续逐步更正。

# RSA算法
RSA是一种非对称加解密算法，可以在加解密、签名验证中使用。在加解密、签名验证过程中，通信双方将使用公钥、私钥进行操作。
本节将首先介绍RSA的数学原理，并举例说明密钥生成过程、加解密过程；进而举例说明并介绍签名验证过程；最后，说明公钥、私钥是如何存储的。

## 欧拉定理
在描述欧拉定理之前，需要陈述如下几个定义：
### 互质关系

> **定义：**
> <center>
> 若两个正整数，除了整数1之外，没有其它公因子，则称这两个正整数为互质关系。
> </center>

<br>
由互质关系的定义可得出几个重要的结论：
> 1. 任意两个质数构成互质关系，如3和7；
> 2. 若$n$为大于1的整数，则$n$和$n-1$构成互质关系，如5和4；
> 3. 若$n$为大于1的奇数，则$n$和$n-2$构成互质关系，如5和3。

互质关系表明了某两个正整数之间的特殊关系，是欧拉函数定义的前提。需要注意的是，不是质数的两个正整数也可以互质，如4和9。
### 欧拉函数

> **定理：**<br>
> 任一大于1的正整数，均可被质因子分解为如下形式：<br>
> <center>
> $$n=p_1^{k_1}p_2^{k_2}\cdots p_r^{k_r}$$
> </center>
> 其中，$p_1$、$p_2$、$\cdots$ $p_r$均为质数，$k_1$、$k_2$、$\cdots$ $k_r$均为正整数。

上述质因子分解定理，将于欧拉函数通用计算公式中使用。

> **定义：**<br>
> 给定任意正整数$n$，在小于等于$n$的正整数中，有$\phi(n)$个正整数与$n$构成互质关系。其中，定义$\phi(n)$为欧拉函数，且<br>
> <center>
> $$\phi(n) = n(1-\frac{1}{p_1})(1-\frac{1}{p_2})\cdots(1-\frac{1}{p_r})$$
> </center>

根据欧拉函数的通用计算公式可知，在小于等于1323的正整数中，有756个正整数与1323互质，其计算过程为：
<center>
$$\phi(1323)=\phi(3^3\times7^2)=1323(1-\frac{1}{3})(1-\frac{1}{7})=756$$
</center>
### 欧拉定理

> **定理：**<br>
> 若两个正整数$a$和$n$互质，则如下等式成立：<br>
> <center>
> $$a^{\phi(n)}\equiv 1\ (mod\ n)$$
> </center>

### 模反元素
根据欧拉定理，可以定义整数$a$的模反元素。

> **定义：**<br>
> 若两个正整数$a$和$n$互质，一定存在一个整数b，使得如下等式成立：<br>
> <center>
> $$ab\equiv 1\ (mod\ n)$$
> </center>
> 其中，定义$b$为$a$对于$n$的模反元素，且
> <center>
> $$b=a^{\phi(n)-1}$$
> </center>

## RSA加解密函数
RSA加解密是在整数环$Z_n$内完成。假设使用RSA加密明文$x$，而表示$x$的位字符串则是$Z_n=\\{0,1,\cdots ,n-1\\}$内的元素。
因此，明文$x$表示的二进制值必然小于$n$，其密文$y$亦然。
### RSA加密函数

> **定义：**<br>
> 给定公钥$e$(encrypt的缩写)和模数$n$，二者组成二元组$(n,e)$。对明文$x$执行RSA加密操作，可得到密文$y$，其中：<br>
> <center>
> $$y\equiv x^e\ (mod\ n)$$
> </center>

### RSA解密函数

> **定义：**<br>
> 已知私钥$d$(decrypt的缩写)和模数$n$，二者组成二元组$(n,d)$。对密文$y$执行RSA解密操作，可得到明文$x$，其中：<br>
> <center>
> $$x\equiv y^d\ (mod\ n)$$
> </center>

### RSA算法证明
已知RSA公钥为$(n,e)$，私钥为$(n,d)$，明文为$x$，经RSA加密得到的密文为$y$，若要使得加解密成立，则需满足：
<center>
$$y^d\equiv (x^e)^d\equiv x^{ed}\equiv x\ (mod\ n)$$
</center>
可以证明，若需保证上式成立，只需满足下式即可：
<center>
$$ed\equiv 1\ (mod\ \phi(n))$$
</center>
即，$d$为$e$对于$\phi(n)$的模反元素；也即私钥为公钥对于$\phi(n)$的模反元素。
## RSA密钥生成步骤
通过前述RSA加解密函数的定义及证明，可总结RSA密钥的生成步骤如下：

> 1. 随机选择两个不相等的大质数$p$和$q$；
> 2. 计算$n=p\times q$；
> 3. 计算$n$的欧拉函数$\phi(n)=(p-1)(q-1)$
> 4. 随机选择一个整数$e$（即公钥），使得$e\in \\{1,2,\cdots ,\phi(n)-1\\}$且$e$与$\phi(n)$互质；
> 5. 计算$e$对于$\phi(n)$的模反元素$d$（即私钥），即二者满足$ed\equiv 1\ (mod\ n)$。

## RSA加解密简例
下面通过一个简单的例子，来说明RSA加解密的工作方式：

假设A想要发送一个经过RSA加密的消息给B。首先B需要生成RSA密钥：

> 1. 随机选择质数$p=3$、$q=11$；
> 2. 计算$n=3\times 11=33$；
> 3. 计算$\phi(n)=\phi(33)=(3-1)\times (11-1)=20$；
> 4. 随机选择公钥$e=3$；
> 5. 使用扩展欧几里得算法计算私钥$d\equiv e^{-1}\equiv 3^{-1} \equiv 7\ (mod\ 20)$。

此时，B即得到了其公钥$(n,e)=(33,3)$、私钥$(n,d)=(33,7)$。

B并将公钥信息$(n,e)=(33, 3)$发送给A，A获取到B的公钥信息后，对消息明文$x=4$进行RSA加密得到密文$y$：

<center>
$$y=x^e=4^3\equiv 31\ (mod\ 33)$$
</center>

B接收到密文$y$后，使用私钥对密文进行解密：

<center>
$$x^\prime = y^d=31^7\equiv 4\ (mod\ 33)$$
</center>

经过上述计算，可以发现B解密得到的信息$x^\prime$与A发送的信息$x$相同。通过此例，可验证前述工作方式的有效性。
## RSA的实际使用
由RSA的密钥生成过程及前述简单的例子可知，RSA加密方已获取到了解密方的公钥信息$(n,e)$。加密方若想破解出解密方的私钥信息，
只需求出$\phi(n)$即可，即对$n$进行因式分解得到质数$p$和$q$。若使用前述RSA例子里的$n=33$做为模数，则很容易求出其质因子（$p=3$、$q=11$）。
因此，在实际使用中，RSA的模数$n$将为一个特别大的整数。

**实际中，我们常说的1024位RSA是指其模数$n$的bit位数。**此时，模数$n$是一个相当大的整数，若要对其进行质因子分解，以当前的算力，
需要相当长的时间（十余年？）方能得出。当前已知被破解RSA的最大长度为768位（通过并行计算花费2年时间于2009年12月12日完成，
相当于使用单核2.2GHz的AMD处理器花费2000年的运算量）：

> $$n=$$<br>
> $$\ \ \ \ \ \ 12301866845301177551304949583849627207728535695953347921973224521517264005$$<br>
> $$\ \ \ \ \ \ 07263657518745202199786469389956474942774063845925192557326303453731548268$$<br>
> $$\ \ \ \ \ \ 50791702612214291346167042921431160222124047927473779408066535141959745985$$<br>
> $$\ \ \ \ \ \ 6902143413$$<br>
> $$\ \ = p\times q=$$<br>
> $$\ \ \ \ \ \ 33478071698956898786044169848212690817704794983713768568912431388982883793$$<br>
> $$\ \ \ \ \ \ 878002287614711652531743087737814467999489$$<br>
> $$\ \ \ \ \ \ \times$$<br>
> $$\ \ \ \ \ \ 36746043666799590428244633799627952632279158164343087642676032283815739666$$<br>
> $$\ \ \ \ \ \ 511279233373417143396810270092798736308917$$

由于RSA加密为一种分组加密算法，明文以分组为单位（固定长度，长度与模数$n$的比特长度相同）进行加密，每个分组的二进制值均小于模数$n$；一般，RSA不适合加密较长的消息。

针对较长消息，通常的做法是：使用RSA加密一个对称加密的密钥，然后再使用该对称密钥对较长的消息进行加密。若确实需要使用RSA对较长消息加密，则需对该消息进行分段处理。

针对长度不足的明文消息，需要对消息进行填充。常用的有三种填充方式：
+ **RSA_PKCS1_PADDING：**

> 最常用的填充方式。
>> 输入：必须比RSA模数长度短至少11字节，不足部分，加密时将随机填充一些数据，这将导致对同样的明文每次加密后的结果均不同，也保证了一定的随机性。<br>
>> 输出：和模数长度相同的密文。<br>

> 因此，对于1024bits的RSA加密，其明文分组最长为$(1024/8-11)=117$字节，相应的密文为128字节。

+ **RSA_PKCS1_OAEP_PADDING：**

> 新推出的填充方式，安全性最高。
>> 输入：必须比RSA模数长度短至少41字节，不足部分，加密时将随机填充一些数据，这将导致对同样的明文每次加密后的结果均不同，也保证了一定的随机性。<br>
>> 输出：和模数长度相同的密文。<br>

> 因此，对于1024bits的RSA加密，其明文分组最长为$(1024/8-41)=87$字节，相应的密文为128字节。其与RSA_PKCS1_PADDING的主要区别为加密前编码方式不同。

+ **RSA_NO_PADDING:**

> 不填充。
>> 输入：明文可以与模数一样长，不足部分，加密时将在明文前面填充0。<br>
>> 输出：和模数长度相同的密文。<br>

## RSA密钥的存储
### 存储格式
生成密钥后，一般会将其存储在文件中。密钥的存储格式一般有两种——PEM和DER。

一般，使用ASN.1语言去描述密钥信息，以保证密钥的可交互性。对密钥的ASN.1结构
进行DER编码，得到的二进制串将被保存于DER文件中。

由于DER文件中存储的二进制串不可读，在某些场景下（如，在github上填写SSH公钥信息）使用较为不便。因此，需要一种可读的存储方式——PEM格式：将DER
文件的二进制串进行BASE64编码，然后在编码后的信息前后分别加上具有说明意义的前缀（`-----BEGIN`）和后缀（`-----END`），最终形成PEM格式文件。
例，一个公钥的PEM格式表示如下：

```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMYfnvWtC8Id5bPKae5yXSxQTt
+Zpul6AnnZWfI2TtIarvjHBFUtXRo96y7hoL4VWOPKGCsRqMFDkrbeUjRrx8iL91
4/srnyf6sh9c8Zk04xEOpK1ypvBz+Ks4uZObtjnnitf0NBGdjMKxveTq+VE7BWUI
yQjtQ8mbDOsiLLvh7wIDAQAB
-----END PUBLIC KEY-----
```

因此，若想获取到公钥的详细信息：首先，需要对前后缀间的内容进行BASE64解码；再对解码后的二进制串做DER解码即可。

### 密钥的ASN.1表示
RSA密钥有多种ASN.1表示方式，分别在不同的标准（如PKCS#1、PKCS#8等）中进行了定义：

+ **公钥(PKCS#1)：**

```
RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
```

+ **公钥(PKCS#8)：**

```
PublicKeyInfo ::= SEQUENCE {
    algorithm       AlgorithmIdentifier,
    PublicKey       BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
    algorithm       OBJECT IDENTIFIER,
    parameters      ANY DEFINED BY algorithm OPTIONAL
}
```

+ **公钥（RFC5280--X.509证书相关）：**

```
SubjectPublicKeyInfo  ::=  SEQUENCE  {
    algorithm            AlgorithmIdentifier,
    subjectPublicKey     BIT STRING
}
AlgorithmIdentifier  ::=  SEQUENCE  {
    algorithm            OBJECT IDENTIFIER,
    parameters           ANY DEFINED BY algorithm OPTIONAL
}
```

+ **私钥（PKCS#1）：**

```
RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

+ **私钥（PKCS#8--不加密）：**

```
PrivateKeyInfo ::= SEQUENCE {
    version         Version,
    algorithm       AlgorithmIdentifier,
    PrivateKey      OCTET STRING
}

AlgorithmIdentifier ::= SEQUENCE {
    algorithm       OBJECT IDENTIFIER,
    parameters      ANY DEFINED BY algorithm OPTIONAL
}
```

+ **私钥（PKCS#8--加密）：**

```
EncryptedPrivateKeyInfo ::= SEQUENCE {
    encryptionAlgorithm  EncryptionAlgorithmIdentifier,
    encryptedData        EncryptedData
}

EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

AlgorithmIdentifier ::= SEQUENCE {
    algorithm            OBJECT IDENTIFIER,
    parameters           ANY DEFINED BY algorithm OPTIONAL
}

EncryptedData ::= OCTET STRING
```

关于密钥存储的说明，均可通过OpenSSL进行验证——未设置密码的RSA私钥采用PKCS#1定义的ASN.1结构进行存储；
公钥采用RFC5280定义的ASN.1结构进行存储。

同时，需要说明的是OpenSSH所使用的公钥存储格式与OpenSSL的不同，但可用openssl工具进行互转。

## RSA数字签名
RSA算法不仅可以用来加解密，也可以用来做数字签名，以保证消息的数据完整性、机密性和不可抵赖性。RSA数字签名算法刚好与加解密算法相反：
发送发使用其私钥对发送信息进行加密，得到签名信息；接收方使用发送方的公钥对签名信息进行解密，并比对解密信息与发送信息是否一致，此过程为验签。

由于RSA算法是一种分组加解密算法，待签名的信息一般较长。因此，一般在签名之前先计算待签名信息的消息摘要，再对该摘要进行签名、验签。故，RSA签名、
验签过程如下：

**RSA签名：**
1. 发送方计算发送信息$x$的消息摘要，记为$H(x)$，如使用SHA-256算法；
2. 发送方使用其私钥$(n,d)$对$H(x)$进行加密，生成签名信息$s$，$s$满足：$s\equiv (H(x))^d\ (mod\ n)$；
3. 发送方将发送信息和签名信息$(x,s)$发送给接收方。

**RSA验签：**
1. 接收方使用发送方的公钥$(n,e)$对签名信息$s$进行解密，得到$H^\prime (x)\equiv s^e\ (mod\ n)$；
2. 接收方计算发送信息$x$的消息摘要$H(x)$；
3. 比较$H(x)$和$H^\prime (x)$是否相同，若相同则验签通过，即证明消息的确为发送方发送的；若不同，则验签不通过。

# ECC（椭圆曲线密码系统）
ECC是基于推广的离散对数问题的，与RSA不同——RSA是基于元素间的乘法操作，而ECC是基于元素间的加法操作。下面我们将首先介绍一些基础的代数知识，进而
对椭圆曲线的基本定义、操作、签名/验签等分别予以介绍。

## 基础代数
### 群

> **定义：**<br>
> 群指的是一个元素集合$G$以及联合$G$内的两个元素的操作$o$的集合。群具有如下属性：
> 1. 群操作$o$是封闭的，即对所有的$a,b\in G$，$aob=c\in G$始终成立；
> 2. 群操作$o$是可结合的，即对所有的$a,b,c\in G$，都有$ao(boc)=(aob)oc$；
> 3. 存在一个元素$1\in G$，对所有的$a\in G$均满足$ao1=1oa=a$，这个元素称为单位元；
> 4. 对每个元素$a\in G$，存在一个元素$a^{-1}\in G$，满足$aoa^{-1}=a^{-1}oa=1$，则$a^{-1}$称为$a$的逆元；
> 5. 如果所有$a,b\in G$都额外满足$aob=boa$，则称群$G$为阿贝尔群或可交换群。

密码学里，经常使用乘法群（即操作$o$为乘法）（如RSA）和加法群（即操作$o$为加法）（如ECC）。

### 有限群

> **定义：**
> 当群$(G,o)$的元素个数为有限个时，则称该群为有限群。群$G$内元素的个数（含单位元）称为群的基或阶，表示为$|G|$。

以下引入两个定理，后文将用到：
> **定理：**<br>
> 对于素数$p$，群$G$都是一个有限循环群；<br>
> 如果$|G|$为素数，则所有满足$a\neq 1 \in G$的元素$a$都是生成元。

### 元素的阶

> **定义：**<br>
> 群$(G,o)$内某元素$a$的阶$ord(a)$指的是满足如下条件的最小正整数$k$：
> <center>
> $a^k=\underbrace{aoao\cdots oa}_{k次}=1$，
> </center>
> 其中$1$是$G$的单位元。

针对椭圆曲线加法群，其操作为加法，单位元为无穷大的虚数点$\vartheta$。

### 循环群

> **定义：**<br>
> 如果群$G$包含一个拥有最大阶$ord(\alpha)=|G|$的元素$\alpha$，则称这个群为循环群。拥有最大阶的元素称为原根（本原元）或生成元。

## 椭圆曲线

> **定义：**<br>
> 有限域$GF(q)(q>3)$上的椭圆曲线$E$是点$P=(x,y)$及一个无穷大虚数点$\vartheta$（单位元）的集合，其中$x,y\in GF(q)$；
> 针对不同的有限域，$x,y$满足如下条件：
> + 若有限域$GF(q)$为素数域，即$q$为素数$p$：
> <center>
> $$y^2\equiv x^3+ax+b\ (mod\ p)$$
> 其中，$a,b\in GF(p)$，且$4a^3+27b^2\neq 0\ (mod\ p)$
> </center>
> +  若有限域$GF(q)$为伽罗华域，即$q$为$2$的整数幂$2^m$：
> <center>
> $$y^2+xy\equiv x^3+ax^2+b\ (in\ GF(q))$$
> 其中，$a,b\in GF(q)$，且$b\neq 0$
> </center>

常用的有限域为素数域，后面我们将针对素数域上的椭圆曲线做详细介绍。

### 椭圆曲线上的群操作
椭圆曲线上的群操作为“加”操作，记为“$+$”。此“加”操作与传统的两数相加不同，为两点相加。两点$P(x_1,y_1)$和$Q(x_2,y_2)$（$P$和$Q$可能为同一点）
相加，可得到第三点$R(x_3,y_3)$，该操作可表示为：
<center>
$$P+Q=R$$
$$(x_1,y_1)+(x_2,y_2)=(x_3,y_3)$$
</center>
通过推导，可得到$R$点的坐标计算公式为：
<center>
$$x_3\equiv s^2-x_1-x_2\ (mod\ p)$$
$$y_3\equiv s(x_1-x_3)-y_1\ (mod\ p)$$
</center>
其中，
<center>
$$s\equiv \begin{cases}\frac{y_2-y_1}{x_2-x_1}\ (mod\ p);当P\neq Q& \\ \frac{3x_1^2+a}{2y_1}\ (mod\ p);当P=Q& \end{cases}$$
</center>
记$\vartheta$为单位元，即$P+\vartheta=P$。若$P+Q=\vartheta$，则称$Q(x_Q,y_Q)$为$P(x_P,y_P)$的逆元。由坐标计算公式可知：
<center>
$$x_Q=x_P$$
$$y_Q=-y_P\equiv p-y_P\ (mod\ p)$$
</center>

### 椭圆曲线参数
椭圆曲线$E:y^2\equiv x^3+ax+b\ (mod\ p)$在有限域$F_p$上的参数$T$为六元组——$T=(p,a,b,G,n,h)$，其中：
+ $p$指定了有限域$F_p$，一般为素数；在做“加法”运算时，均为模$p$运算；
+ $a,b \in F_p$指定了椭圆曲线$E$；
+ $G=(x_G,y_G)$为椭圆曲线$E$上的基点，一般为生成元；
+ $n$为基点$G$的阶，为一个素数；
+ $h=\|E\|/n$且$h\leq 4$为辅因子，一般为1。

由此可知，若$h$为1，则基点$G$为生成元，曲线$E$上的所有点（包含单位元虚数点）均可由$G$生成；
若$h>1$，则基点$G$不是生成元，其只能生成部分元素。

### 举例说明
已知椭圆曲线的参数$T=(17,2,2,(5,1),19,1)$，则：
+ 椭圆曲线为$E:y^2\equiv x^3+2x+2\ (mod\ 17)$；
+ 由于$p=17$为素数，曲线上所有点形成一个循环群；
+ 由于$h=1$，则基点$G(5,1)$为生成元，可由基点计算出所有点；
+ 由$n=19,h=1$可得，曲线共有19个点。

记$gG$为$g$个$G$点相加，其中$g$为整数，$G$为椭圆曲线上的点。下面将计算曲线上所有的点（共19个）：
> $$2G=(5,1)+(5,1)=(6,3)$$<br>
> $$3G=2G+G=(10,6)$$<br>
> $$4G=(3,1)$$<br>
> $$5G=(9,16)$$<br>
> $$6G=(16,13)$$<br>
> $$7G=(0,6)$$<br>
> $$8G=(13,7)$$<br>
> $$9G=(7,6)$$<br>
> $$10G=(7,11)$$<br>
> $$11G=(13,10)$$<br>
> $$12G=(0,11)$$<br>
> $$13G=(16,4)$$<br>
> $$14G=(9,1)$$<br>
> $$15G=(3,16)$$<br>
> $$16G=(10,11)$$<br>
> $$17G=(6,14)$$<br>
> $$18G=(5,16)$$<br>
> $$19G=\vartheta$$<br>

## ECC密钥
我们可以根据SEC1标准中的规定生成椭圆曲线参数，但自己生成的参数可能会存在一些“trap”。因此，我们可以使用SEC2内的推荐参数。
后文将假设椭圆曲线参数已生成完毕。在已定参数$T=(p,a,b,G,n,h)$的椭圆曲线下，ECC私钥$d$为某一整数，ECC公钥$Q$为相应的某一椭圆点。下面将介绍如何
生成ECC密钥：
> 1. 在$[1,n-1]$范围内随机选取整数$d$，记为ECC私钥；<br>
> 2. 计算公钥$Q=dG$。<br>

### ECC公钥表示形式
由椭圆曲线方程可知，若已知曲线上的某一点$Q(x_Q,y_Q)$的横坐标$x_Q$，则可计算出$y_Q^2$。此时，我们可以得到两个点$Q_1(x_Q,y_{Q1})$和$Q_2(x_Q,y_{Q2})$。
下面我们来分析点$Q_1$和$Q_2$间的关系：<br>
> 由于$y_{Q1}^2=y_{Q2}^2$，所以$y_{Q1}=-y_{Q2}\equiv p-y_{Q2}\ (mod\ p)$<br>
> 又由于$p$为素数，所以$y_{Q1}$和$y_{Q2}$一个应为奇数，另一个应为偶数。<br>

因此，若已知点$Q$的横坐标$x_Q$和纵坐标的奇偶性，那就可以确定点$Q$。此时，可以只用1bit（纵坐标最低bit位：0或1）来表示点的纵坐标，即为IEEE 1363a-2004中
提出的点压缩表示；使用较少字节来表示椭圆点的代价就是需要增加一些计算量，这需要在实际应用中做取舍。IEEE 1363a-2004中提出了多种椭圆点表示方式，在此只
举出常用的几种，其余的可查阅该标准：<br>
使用八字节组$PO=PC||X||Y$来表示椭圆点，其中$PC$为一字节，用来区分椭圆点的表示形式，必要时，其最低bit位用来表示纵坐标的奇偶性。<br>

|表示形式|PC|X|Y|
|:---:|:---:|:---:|:---:|
|非压缩|0000 0100|$x_Q$|$y_Q$|
|LSB压缩|0000 001$\hat{y}$|$x_Q$|空|

其中，$\hat{y}$为0（当纵坐标为偶数时）或者1（当纵坐标为奇数时）。

### ECC密钥ASN.1表示
如同RSA密钥一样，ECC密钥也使用ASN.1语言进行描述，ECC公钥、密钥的ASN.1表示简列如下（详细内容可参见SEC1-v2附录C.3和C.4）。

+ **ECC公钥的ASN.1表示：**
```
SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm AlgorithmIdentifier {{ECPKAlgorithms}} (WITH COMPONENTS {algorithm, parameters}),
    subjectPublicKey BIT STRING
}
```

+ **ECC私钥的ASN.1表示：**
```
ECPrivateKey ::= SEQUENCE {
    version INTEGER {ecPrivkeyVer1(1)} (ecPrivkeyVer1),
    privateKey OCTET STRING,
    parameters [0] ECDomainParameters {{ SECGCureveNames }} OPTIONAL,
    publicKey [1] BIT STRING OPTIONAL
}
```

## ECDSA(数字签名)
如同RSA，ECC也同样可以用来做数字签名，即ECDSA。一般情况下，ECDSA签名由一对整数$(r,s)$组成；若使用SEC1-v2第4章中提到的快速签名/验签时，$r$将由椭圆点取代。
### ECDSA签名
使用ECDSA对消息$M$生成签名$(r,s)$的过程如下：
1. 在$[1,n-1]$范围内随机选取临时私钥$k$；
2. 计算临时公钥$R(x_R,y_R)=kG$；
3. 设置$r=x_R$；
4. 计算$s\equiv k^{-1}(HASH(M)+dr)\ (mod\ p)$

其中，$d$为签名方的私钥。

### ECDSA验签
使用ECDSA验证消息$M$的签名$(r,s)$的过程如下：
1. 计算$u_1\equiv s^{-1}HASH(M)\ (mod\ p)$；
2. 计算$u_2\equiv s^{-1}r\ (mod\ p)$；
3. 计算$R(x_R,y_R)\equiv u_1G+u_2Q$；
4. 若$x_R$与$r$相等，则验签通过；否则，不通过。

其中，$Q$为签名方的公钥。

### 快速签名/验签
由前述签名/验签过程可知，$r$实际为临时公钥$R$的横坐标，SEC1-v2中提出，若签名中也包含纵坐标，即签名为$(R,s)$，将加快签名/验签过程。详细内容，可参考该标准。
