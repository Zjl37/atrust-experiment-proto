# aTrust

调试环境：VMware Ubuntu 20.04

在校内调试似乎会走直连的线路，不经过转发。用clash强行绕过：

```
hosts:
  'vpn.zju.edu.cn': 210.32.129.102
rules:
  - IP-CIDR,10.3.9.92/32,REJECT-DROP,no-resolve
  - IP-CIDR,10.3.9.93/32,REJECT-DROP,no-resolve
  - IP-CIDR,10.3.9.94/32,REJECT-DROP,no-resolve
  - IP-CIDR,183.157.160.144/32,proxy,no-resolve
  - IP-CIDR,210.32.174.64/32,proxy,no-resolve
  - IP-CIDR,218.108.88.252/32,proxy,no-resolve
  - IP-CIDR,39.174.144.32/32,proxy,no-resolve
  - DOMAIN-SUFFIX,vpn.zju.edu.cn,proxy
  - PROCESS-NAME,vmnat.exe,proxy
```


## 前端登录

1. 前端使用electron开发，按 Ctrl+Shift+I :)。
2. 网页登录，需要切换到Android UA。

图形验证码，短信验证码

复现：`web_login.py`


## 后端流量转发

`/usr/share/sangfor/aTrust/resources/bin/aTrustXtunnel-64`

尝试ida分析 + frida ssl_logger抓包SSL，不好用...

```
sudo -E .venv/bin/python ssl_logger.py -v `ps ax | grep -i aTrustXtunnel-64$ | cut -d " " -f 1` -p logs/1.pcap
```

- sid：authCheck接口返回的cookie
- appId：clientResource接口
- deviceId：生成方式未知，固定
- connectionId, signKey：随机？似乎并不重要


tcp转发流程，模拟`curl http://speedtest.zju.edu.cn/getIP.php`：

1. ~~首次使用sid初始化~~ 似乎并不重要

    ```
    [SSL_write]
    00000000: 05 01 85                                          ...

    [SSL_read]
    00000000: 54 68 69 73 20 69 73 20  74 68 65 20 70 61 63 6B  This is the pack
    00000010: 65 74 20 72 65 74 75 72  6E 20 64 61 74 61 20 75  et return data u
    00000020: 73 65 64 20 62 79 20 54  43 50 20 74 65 73 74 20  sed by TCP test 
    00000030: 0A                                                .

    # header = 05 01 D0 53 00
    # length = 00 53

    [SSL_write]
    00000000: 05 01 D0 53 00 00 53 7B  22 73 69 64 22 3A 22 63  ...S..S{"sid":"c
    00000010: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  83bc12e-xxxx-xxx
    00000020: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  x-xxxx-xxxxxxxxx
    00000030: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  xxx_xxxxxxxx-xxx
    00000040: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  x-xxxx-xxxx-xxxx
    00000050: xx xx xx xx xx xx xx xx  22 7D                    xxxxxxxx"}
    00000050:                                05 04 00 01 00 00            ......
    00000060: 00 00 00 00                                       ....

    [SSL_read]
    00000000: 05 D0                                             ..

    [SSL_read]
    00000000: 53 00 00 38                                       S..8

    [SSL_read]
    00000000: 7B 22 63 6F 64 65 22 3A  30 2C 22 64 61 74 61 22  {"code":0,"data"
    00000010: 3A 7B 22 64 65 76 69 63  65 49 44 22 3A 22 43 42  :{"deviceID":"CB
    00000020: xx xx xx xx xx xx xx xx  2C 22 6D 65 73 73 61 67  XXXXXX"},"messag
    00000030: 65 22 3A 22 4F 4B 22 7D                           e":"OK"}

    [SSL_read]
    00000000: 05 00 00 01 0A BE 80 0A  00 00                    ..........

    # ip = 0A BE 80 0A ?
    ```

2. 发送请求头

    ```
    # header = 05 01 81 53 03
    # length = 03 7C

    [SSL_write]
    00000000: 05 01 81 53 03 03 7C 7B  22 73 69 64 22 3A 22 63  ...S..|{"sid":"c
    00000010: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  xxxxxxx-xxxx-xxx
    00000020: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  x-xxxx-xxxxxxxxx
    00000030: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  xxx_xxxxxxxx-xxx
    00000040: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  x-xxxx-xxxx-xxxx
    00000050: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  xxxxxxxx","appId
    00000060: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  ":"xxxxxxxx-xxxx
    00000070: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  -xxxx-xxxx-xxxxx
    00000080: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  xxxxxxx","url":"
    00000090: 74 63 70 3A 2F 2F 73 70  65 65 64 74 65 73 74 2E  tcp://speedtest.
    000000A0: 7A 6A 75 2E 65 64 75 2E  63 6E 3A 38 30 22 2C 22  zju.edu.cn:80","
    000000B0: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  deviceId":"xxxxx
    000000C0: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  xxxxxxxxxxxxxxxx
    000000D0: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  xxxxxxxxxxx","co
    000000E0: 6E 6E 65 63 74 69 6F 6E  49 64 22 3A 22 35 37 38  nnectionId":"XXX
    000000F0: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000100: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXX-00
    00000110: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  0000000000000000
    00000120: 34 39 22 2C 22 70 72 6F  63 48 61 73 68 22 3A 22  00","procHash":"
    00000130: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000140: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000150: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000160: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000170: 22 2C 22 75 73 65 72 4E  61 6D 65 22 3A 22 32 32  ","userName":"22
    00000180: 32 32 32 32 32 32 22 2C  22 72 63 41 70 70 6C 69  222222","rcAppli
    00000190: 65 64 49 6E 66 6F 22 3A  30 2C 22 6C 61 6E 67 22  edInfo":0,"lang"
    000001A0: 3A 22 65 6E 2D 55 53 22  2C 22 64 65 73 74 41 64  :"en-US","destAd
    000001B0: 64 72 22 3A 22 73 70 65  65 64 74 65 73 74 2E 7A  dr":"speedtest.z
    000001C0: 6A 75 2E 65 64 75 2E 63  6E 3A 38 30 22 2C 22 64  ju.edu.cn:80","d
    000001D0: 65 73 74 49 50 22 3A 22  31 30 2E 32 30 32 2E 34  estIP":"10.202.4
    000001E0: 31 2E 38 31 22 2C 22 65  6E 76 22 3A 7B 22 61 70  1.81","env":{"ap
    000001F0: 70 6C 69 63 61 74 69 6F  6E 22 3A 7B 22 72 75 6E  plication":{"run
    00000200: 74 69 6D 65 22 3A 7B 22  70 72 6F 63 65 73 73 22  time":{"process"
    00000210: 3A 7B 22 6E 61 6D 65 22  3A 22 63 75 72 6C 22 2C  :{"name":"curl",
    00000220: 22 64 69 67 69 74 61 6C  5F 73 69 67 6E 61 74 75  "digital_signatu
    00000230: 72 65 22 3A 22 54 72 75  73 74 41 70 70 43 6C 6F  re":"TrustAppClo
    00000240: 73 65 64 22 2C 22 70 6C  61 74 66 6F 72 6D 22 3A  sed","platform":
    00000250: 22 4C 69 6E 75 78 22 2C  22 66 69 6E 67 65 72 70  "Linux","fingerp
    00000260: 72 69 6E 74 22 3A 22 46  30 44 41 39 35 35 44 34  rint":"F0DA955D4
    00000270: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000280: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000290: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    000002A0: 30 44 46 39 43 46 46 22  2C 22 64 65 73 63 72 69  0DF9CFF","descri
    000002B0: 70 74 69 6F 6E 22 3A 22  54 72 75 73 74 41 70 70  ption":"TrustApp
    000002C0: 43 6C 6F 73 65 64 22 2C  22 70 61 74 68 22 3A 22  Closed","path":"
    000002D0: 2F 75 73 72 2F 62 69 6E  2F 63 75 72 6C 22 2C 22  /usr/bin/curl","
    000002E0: 76 65 72 73 69 6F 6E 22  3A 22 54 72 75 73 74 41  version":"TrustA
    000002F0: 70 70 43 6C 6F 73 65 64  22 2C 22 73 65 63 75 72  ppClosed","secur
    00000300: 69 74 79 5F 65 6E 76 22  3A 22 6E 6F 72 6D 61 6C  ity_env":"normal
    00000310: 22 7D 2C 22 70 72 6F 63  65 73 73 5F 74 72 75 73  "},"process_trus
    00000320: 74 65 64 22 3A 22 54 52  55 53 54 45 44 22 7D 7D  ted":"TRUSTED"}}
    00000330: 7D 2C 22 78 52 65 71 75  65 73 74 53 69 67 22 3A  },"xRequestSig":
    00000340: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  "XXXXXXXXXXXXXXX
    00000350: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000360: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000370: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  XXXXXXXXXXXXXXXX
    00000380: 37 22 7D                                          X"}
    00000380:          05 01 01 01 0A  CA 29 51 00 50              ......)Q.P

    # header = 05 01 01 01
    # ip = 0A CA 29 51
    # port = 00 50
    # 10.202.41.81:80
    ```

3. 发送tcp数据包内容

    ```
    # header = 01 00
    # length = 00 5D

    [SSL_write]
    00000000: 01 00 00 5D 47 45 54 20  2F 67 65 74 49 50 2E 70  ...]GET /getIP.p
    00000010: 68 70 20 48 54 54 50 2F  31 2E 31 0D 0A 48 6F 73  hp HTTP/1.1..Hos
    00000020: 74 3A 20 73 70 65 65 64  74 65 73 74 2E 7A 6A 75  t: speedtest.zju
    00000030: 2E 65 64 75 2E 63 6E 0D  0A 55 73 65 72 2D 41 67  .edu.cn..User-Ag
    00000040: 65 6E 74 3A 20 63 75 72  6C 2F 37 2E 36 38 2E 30  ent: curl/7.68.0
    00000050: 0D 0A 41 63 63 65 70 74  3A 20 2A 2F 2A 0D 0A 0D  ..Accept: */*...
    00000060: 0A                                                .

    [SSL_read]
    00000000: 05 81                                             ..

    [SSL_read]
    00000000: 53 00 00 96                                       S...

    # length = 00 96

    [SSL_read]
    00000000: 7B 22 65 78 74 22 3A 7B  22 64 65 76 69 63 65 49  {"ext":{"deviceI
    00000010: 64 22 3A 22 32 45 2A 2A  2A 2A 38 31 22 2C 22 6E  d":"2E****81","n
    00000020: 61 6D 65 49 6E 43 6C 75  73 74 65 72 22 3A 22 E4  ameInCluster":".
    00000030: xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  ...........","he
    00000040: 61 72 74 62 65 61 74 49  70 49 6E 43 6C 75 73 74  artbeatIpInClust
    00000050: 65 72 22 3A 22 31 2E 31  2E 31 2E 32 22 7D 2C 22  er":"1.1.1.2"},"
    00000060: 6D 65 73 73 61 67 65 22  3A 22 4F 4B 22 2C 22 64  message":"OK","d
    00000070: 61 74 61 22 3A 7B 22 76  69 70 22 3A 22 31 30 2E  ata":{"vip":"10.
    00000080: 31 39 30 2E 31 36 30 2E  37 36 22 7D 2C 22 63 6F  190.160.76"},"co
    00000090: 64 65 22 3A 30 7D                                 de":0}

    [SSL_read]
    00000000: 05 00 01 01                                       ....

    [SSL_read]
    00000000: 00 00 00 00 00 00                                 ......

    [SSL_read]
    00000000: 01 00 00 A2                                       ....

    # header = 01 00
    # length = 00 A2

    [SSL_read]
    00000000: 48 54 54 50 2F 31 2E 31  20 32 30 30 20 4F 4B 0D  HTTP/1.1 200 OK.
    00000010: 0A 44 61 74 65 3A 20 57  65 64 2C 20 30 34 20 4A  .Date: Wed, 04 J
    00000020: 75 6E 20 32 30 32 35 20  30 39 3A 31 34 3A 34 34  un 2025 09:14:44
    00000030: 20 47 4D 54 0D 0A 53 65  72 76 65 72 3A 20 41 70   GMT..Server: Ap
    00000040: 61 63 68 65 2F 32 2E 34  2E 31 38 20 28 55 62 75  ache/2.4.18 (Ubu
    00000050: 6E 74 75 29 0D 0A 43 6F  6E 74 65 6E 74 2D 4C 65  ntu)..Content-Le
    00000060: 6E 67 74 68 3A 20 31 33  0D 0A 43 6F 6E 74 65 6E  ngth: 13..Conten
    00000070: 74 2D 54 79 70 65 3A 20  74 65 78 74 2F 70 6C 61  t-Type: text/pla
    00000080: 69 6E 3B 20 63 68 61 72  73 65 74 3D 75 74 66 2D  in; charset=utf-
    00000090: 38 0D 0A 0D 0A 31 30 2E  31 39 30 2E 31 36 30 2E  8....10.190.160.
    000000A0: 37 36                                             76
    ```

4. 关闭连接

    ```
    [SSL_write]
    00000000: 01 01 00 00                                       ....

    [SSL_read]
    00000000: 01 01 30 30                                       ..00
    ```


复现：`atrust/protocol.go`

# 参考资料

- [南京大学 SSL VPN 协议分析与实现](https://blog.lyc8503.net/post/nju-ssl-vpn-protocol/)
