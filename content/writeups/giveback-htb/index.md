---
title: "Giveback - HTB"
date: 2025-11-01
summary: ""
layout: "single"
tags: ["Linux", "Medium", "HTB"]
draft: true
---

## Recon inicial

Iniciaremos com o de sempre, o scan de portas. Estarei usando o [RustScan]() pra isso:
```bash
rustscan -a 10.129.124.49 -u 5000 -- -sV

PORT      STATE SERVICE REASON         VERSION                                                                                                                                                
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)                                                                                          
80/tcp    open  http    syn-ack ttl 62 nginx 1.28.0                                                                                                                                           
30686/tcp open  unknown syn-ack ttl 63                                                                                                                                                        
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port30686-TCP:V=7.93%I=7%D=11/1%Time=69066481%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Bal
SF:ancing-Endpoint-Weight:\x201\r\nDate:\x20Sat,\x2001\x20Nov\x202025\x201
SF:9:50:28\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\
SF:n\t\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-servic
SF:e\"\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20t
SF:rue\n}")%r(HTTPOptions,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20
SF:application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Balanc
SF:ing-Endpoint-Weight:\x201\r\nDate:\x20Sat,\x2001\x20Nov\x202025\x2019:5
SF:0:28\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t
SF:\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-service\"
SF:\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20true
SF:\n}")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnec
SF:tion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r
SF:(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,132,"HTTP/1\.0\x20200\x
SF:20OK\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nX-Load-Balancing-Endpoint-Weight:\x201\r\nDate:\x20Sat,\x20
SF:01\x20Nov\x202025\x2019:50:56\x20GMT\r\nContent-Length:\x20127\r\n\r\n{
SF:\n\t\"service\":\x20{\n\t\t\"namespace\":\x20\"default\",\n\t\t\"name\"
SF::\x20\"wp-nginx-service\"\n\t},\n\t\"localEndpoints\":\x201,\n\t\"servi
SF:ceProxyHealthy\":\x20true\n}");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Encontramos duas portas padrões e uma porta alta desconhecida. Po