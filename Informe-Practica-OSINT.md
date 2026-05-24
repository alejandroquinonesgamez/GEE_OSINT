# Reconocimiento DNS de una empresa

**Autor:** Alejandro Quiñones Gámez  
**Asignatura:** Hacking Ético  
**Curso:** Curso de Especialización en Ciberseguridad en Tecnologías de la Información

---

## Introducción

En la fase de descubrimiento o *footprinting* de un test de intrusión, la recolección de información sobre la infraestructura del objetivo constituye un paso previo imprescindible. Las técnicas empleadas pueden clasificarse en **pasivas**, cuando no interactúan directamente con los sistemas del blanco y no dejan rastro identificable, y **activas**, cuando generan consultas DNS u otras interacciones registrables en los servidores consultados.

El protocolo **DNS** (Domain Name System) traduce nombres de dominio en direcciones IP y otros datos de configuración. La estructura jerárquica de nombres —FQDN (*Fully Qualified Domain Name*)— se interpreta de derecha a izquierda: raíz (`.`), dominio de nivel superior o **TLD**, dominio de segundo nivel y subdominios. Los registros más relevantes en reconocimiento son:

| Registro | Función |
|----------|---------|
| **A / AAAA** | Resolución de nombre a IPv4 / IPv6 |
| **NS** | Servidores de nombres autoritativos de la zona |
| **MX** | Servidores de correo (con prioridad) |
| **CNAME** | Alias hacia otro nombre |
| **TXT** | Metadatos (p. ej. SPF para correo) |
| **PTR** | Resolución inversa (IP → nombre) |

La presente práctica aplica técnicas de reconocimiento DNS sobre **Grupo GEE**, grupo empresarial del sector electromédico y servicios asociados, con presencia en varios dominios y TLD. El trabajo se ejecuta desde **Kali Linux**, siguiendo la metodología descrita en los materiales de la unidad (*Reconocimiento DNS*, *Introducción a DNS* y *Cheat Sheet Reconocimiento DNS*).

Herramientas empleadas: `dig`, `dnsenum`, `whois`, `nmap` (script NSE `dns-cache-snoop`), **recon-ng** (módulo Hackertarget), **DNSDumpster**, **Sublist3r** y **theHarvester** (consulta complementaria de dominios relacionados).

---

## 1. Descripción del objetivo

### Objetivo

Identificar y caracterizar la organización seleccionada como blanco de reconocimiento, justificando su idoneidad para un ejercicio de enumeración DNS.

### Descripción de Grupo GEE

**Grupo GEE** es un conjunto empresarial de tamaño mediano-grande con actividad en el sector electromédico, distribución y servicios digitales asociados. Dispone de presencia pública en Internet mediante varios dominios registrados, lo que ofrece superficie suficiente para aplicar las técnicas de la práctica.

| Dominio | Rol inferido |
|---------|----------------|
| `grupo-gee.com` | Dominio corporativo principal |
| `geelectromedico.com` | División electromédica |
| `ibermansa.com` | Entidad del grupo (gestión, CRM, intranet) |
| `greelocal.com` | Servicios locales / formación / acceso remoto |
| `iberdata.pt` | Presencia en Portugal (ccTLD `.pt`) |

La infraestructura observada combina hosting propio o de terceros en España (**Cyberneticos**, Cádiz), delegación DNS en **GoDaddy** o **Puntum Consulting**, y servicios de correo en **Microsoft 365** (*mail.protection.outlook.com*).

### Procedimiento

Se inicia el reconocimiento pasivo con la herramienta web **DNSDumpster**, introduciendo el dominio raíz `grupo-gee.com` como punto de partida del análisis.

![Consulta inicial en DNSDumpster para grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster.png)

### Resultados y análisis

Grupo GEE cumple los requisitos del enunciado: es una organización con múltiples dominios, subdominios publicados, servidores NS/MX diferenciados y rangos de IP consultables en RIR. La diversidad de TLD (`.com`, `.pt`) y de proveedores DNS facilita comparar configuraciones y detectar posibles debilidades (transferencia de zona, cache snooping).

---

## 2. Obtención de dominios TLD

### Objetivo

Identificar los dominios de nivel superior y las variantes de nombre asociadas al grupo objetivo, obteniendo inteligencia sobre su presencia geográfica y estructura de marcas.

### Marco teórico

Los **TLD** se clasifican en:

- **gTLD** (*generic*): `.com`, `.org`, `.net`, etc.
- **ccTLD** (*country code*): `.es`, `.pt`, `.fr`, etc.
- **sTLD** (*sponsored*): `.edu`, `.gov`, `.cat`, etc.

La herramienta `dnsrecon` permite enumerar TLD alternativos con `dnsrecon -t tld -d <dominio_base>`. En este ejercicio, la correlación de dominios se realiza mediante reconocimiento pasivo y activo sobre los activos ya identificados del grupo.

### Procedimiento

**Paso 1.** Consulta de dominios del grupo mediante recon-ng (workspace `gee`) y theHarvester sobre los dominios principales:

```bash
recon-ng -w gee
marketplace install recon/domains-hosts/hackertarget
modules load recon/domains-hosts/hackertarget
options set SOURCE grupo-gee.com
run
```

```bash
theharvester -d grupo-gee.com -l 500 -b duckduckgo,yahoo
theharvester -d geelectromedico.com -l 500 -b duckduckgo,yahoo
theharvester -d asimesa.com -l 500 -b duckduckgo,yahoo
```

**Paso 2.** Análisis de resolución DNS inicial con `dnsenum` sin diccionario sobre el dominio corporativo:

```bash
dnsenum grupo-gee.com
```

![Enumeración DNS básica de grupo-gee.com con dnsenum](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum.png)

### Resultados

| Dominio | TLD | Tipo | IP principal (A) | Proveedor DNS (NS) |
|---------|-----|------|------------------|---------------------|
| `grupo-gee.com` | `.com` | gTLD | 164.138.212.77 | GoDaddy (domaincontrol.com) |
| `geelectromedico.com` | `.com` | gTLD | 164.138.212.77 | GoDaddy |
| `ibermansa.com` | `.com` | gTLD | 82.223.212.16 | GoDaddy |
| `greelocal.com` | `.com` | gTLD | — | GoDaddy |
| `iberdata.pt` | `.pt` | ccTLD | 164.138.212.77 | Puntum Consulting |
| `asimesa.com` | `.com` | gTLD | — | Relacionado (theHarvester) |

Durante las pruebas de cache snooping también se incluyó `greelocal.com` como dominio del ecosistema GEE. La presencia de **iberdata.pt** confirma expansión geográfica hacia Portugal mediante ccTLD.

En `geelectromedico.com`, theHarvester identificó correos públicos (`informacion@geelectromedico.com`, `calento@geelectromedico.com`), lo que refuerza la vinculación del dominio al grupo.

### Resultados y análisis

El grupo opera principalmente bajo gTLD `.com`, con una excepción estratégica en `.pt` para el mercado portugués. La IP **164.138.212.77** aparece como punto de convergencia web para `grupo-gee.com`, `geelectromedico.com` e `iberdata.pt`, lo que sugiere hosting compartido en el CPD de Cyberneticos. `ibermansa.com` utiliza además el rango **82.159.201.0/24** para servicios internos.

---

## 3. Obtención de subdominios

### Objetivo

Descubrir nombres de host y subdominios públicos del grupo mediante técnicas activas (fuerza bruta DNS, consultas a APIs) y pasivas (DNSDumpster, Hackertarget).

### Procedimiento

#### Paso 1. Enumeración con dnsenum y diccionario

Se emplea el diccionario `Capturas/OSINT/mini_dict.txt` (~5000 entradas) con `dnsenum`:

```bash
dnsenum geelectromedico.com -f Capturas/OSINT/mini_dict.txt
dnsenum greelocal.com -f Capturas/OSINT/mini_dict.txt
dnsenum iberdata.pt -f Capturas/OSINT/mini_dict.txt
dnsenum ibermansa.com -f Capturas/OSINT/mini_dict.txt
```

![Brute force DNS sobre geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20geelectromedico.png)

![Brute force DNS sobre greelocal.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20greelocal.png)

![Brute force DNS sobre iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20iberdata.png)

![Brute force DNS sobre ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20Iberman.png)

#### Paso 2. Reconocimiento con recon-ng (Hackertarget)

```bash
recon-ng -w gee
marketplace install recon/domains-hosts/hackertarget
modules load recon/domains-hosts/hackertarget
options set SOURCE grupo-gee.com
run
# Repetir cambiando SOURCE para cada dominio
show hosts
```

![Módulo Hackertarget sobre grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Hacertarget%20grupo-gee.png)

![Hosts consolidados en workspace gee](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Hackertarget%20all.png)

#### Paso 3. Sublist3r (enumeración pasiva multi-fuente)

```bash
sublist3r -d grupo-gee.com
```

![Intento de enumeración con Sublist3r (error)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Sublist3r.png)

#### Paso 4. DNSDumpster (reconocimiento pasivo)

Consultas en https://dnsdumpster.com para cada dominio principal.

![Mapa DNS de grupo-gee.com en DNSDumpster](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20grupo-gee1.png)

![Detalle de registros grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20grupo-gee2.png)

![Grafo de relaciones DNS grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20grupo-gee-grafo.png)

![Mapa DNS geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20geelectromedico1.png)

![Detalle geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20geelectromedico2.png)

![Grafo geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20geelectromedico_grafo.png)

![Mapa DNS ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20ibermansa1.png)

![Detalle ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20ibermansa2.png)

![Grafo ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20ibermansa_grafo.png)

![Mapa DNS iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20iberdata1.png)

![Detalle iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20iberdata2.png)

![Grafo iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20iberdata_grafo.png)

### Tabla resumen de subdominios identificados

#### grupo-gee.com / geelectromedico.com

| Subdominio | IP / destino | Servicio inferido |
|------------|--------------|-------------------|
| `www.grupo-gee.com` | 164.138.212.77 | Web corporativa |
| `www.geelectromedico.com` | 164.138.212.77 | Web |
| `smtp.geelectromedico.com` | 82.159.201.20 | Correo saliente |
| `webmail.geelectromedico.com` | 142.251.168.121 (Google) | Webmail Google |
| `drive.geelectromedico.com` | 142.251.168.121 (Google) | Google Drive |
| `calendario.geelectromedico.com` | 142.251.168.121 (Google) | Google Calendar |
| `autodiscover.geelectromedico.com` | Microsoft 365 | Autodiscover O365 |
| `autodiscover.o365.geelectromedico.com` | Microsoft 365 | O365 |
| `reservas.geelectromedico.com` | 206.189.249.143 (takeaspot) | Reservas externas |
| `academiavirtual.geelectromedico.com` | 82.159.201.24 | Formación (Hackertarget) |

#### ibermansa.com

| Subdominio | IP | Servicio inferido |
|------------|-----|-------------------|
| `www.ibermansa.com` | 82.223.212.16 | Web |
| `intranet.ibermansa.com` | 82.159.201.21 | Intranet |
| `crm.ibermansa.com` | 82.159.201.22 | CRM |
| `actas.ibermansa.com` | 82.159.201.20 | Gestión documental |
| `mail`, `ftp`, `smtp`, `webmail` | 82.159.201.x | Correo y ficheros |
| `sftp`, `bi`, `comercial`, `encuestas`, `acceso` | 82.159.201.x | Servicios internos |

#### greelocal.com

| Subdominio | IP | Servicio inferido |
|------------|-----|-------------------|
| `oficinavirtual.greelocal.com` | 82.159.201.25 | Oficina virtual |
| `aulavirtual.greelocal.com` | 82.159.201.26 | Aula virtual |
| `adfs.greelocal.com` | 82.159.201.24 | Active Directory FS |
| `sso.greelocal.com` | 82.159.201.20 | Single Sign-On |
| `sftp.greelocal.com` | 82.159.203.15 | SFTP |
| `cursos.greelocal.com` | 91.142.211.26 | Plataforma cursos |
| `upgrade.greelocal.com` | 51.68.119.55 | Actualizaciones (OVH) |

#### iberdata.pt

| Subdominio | IP | Servicio inferido |
|------------|-----|-------------------|
| `www.iberdata.pt` | 164.138.212.77 | Web |
| `mail.iberdata.pt` | 195.23.128.250 | Correo legacy |
| `smtp.iberdata.pt` | 195.23.128.251 | SMTP |
| `pop.iberdata.pt` | 195.23.128.248 | POP3 |
| `ns1/ns2.iberdata.pt` | 194.79.69.x | NS internos declarados |
| `autodiscover.iberdata.pt` | Microsoft 365 | Autodiscover |

### Resultados y análisis

La combinación de **dnsenum** (fuerza bruta) y **Hackertarget** (vía recon-ng) proporciona la mayor cantidad de subdominios accionables. Destacan:

- **Subdominios internos** (`intranet`, `crm`, `sso`, `adfs`) que delatan aplicaciones de gestión expuestas a Internet.
- **Dependencias de terceros**: Google Workspace, Microsoft 365, takeaspot.net, OVH.
- **Sublist3r** falló por bloqueo de VirusTotal (`IndexError` / peticiones bloqueadas); se documenta como limitación de herramientas pasivas automatizadas.
- **DNSDumpster** aporta contexto de banners (Apache, Pure-FTPd en 164.138.212.77) y **RevIP: 413** dominios en la misma IP, indicando hosting compartido con riesgo de vecindad.

---

## 4. Obtención de servidores de nombres (NS) y servidores de correo (MX)

### Objetivo

Identificar los servidores DNS autoritativos y de correo del grupo, analizar su proveedor y las implicaciones de seguridad.

### Procedimiento

**Paso 1.** Consulta directa con `dig`:

```bash
dig ns grupo-gee.com +short
dig mx grupo-gee.com +short
dig ns geelectromedico.com +short
dig mx geelectromedico.com +short
dig ns ibermansa.com +short
dig mx ibermansa.com +short
dig ns iberdata.pt +short
dig mx iberdata.pt +short
```

![Registros NS y MX de los cuatro dominios principales](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/ns%2Bmx.png)

**Paso 2.** Verificación complementaria con `dnsenum` (secciones Name Servers y Mail Servers de cada dominio).

### Resultados

#### Servidores de nombres (NS)

| Dominio | Servidores NS | IPs NS |
|---------|---------------|--------|
| `grupo-gee.com` | ns13/ns14.domaincontrol.com | 97.74.106.7, 173.201.74.7 |
| `geelectromedico.com` | ns13/ns14.domaincontrol.com | 97.74.106.7, 173.201.74.7 |
| `ibermansa.com` | ns55/ns56.domaincontrol.com | 97.74.107.28, 173.201.75.28 |
| `iberdata.pt` | ns1/ns2.puntumconsulting.com | 164.138.212.77, 5.79.96.3 |
| `greelocal.com` | ns01/ns02.domaincontrol.com | 97.74.100.1, 173.201.68.1 |

Los dominios `.com` del grupo delegan DNS en **GoDaddy** (*domaincontrol.com*). `iberdata.pt` utiliza **Puntum Consulting**, coherente con el hosting en Cyberneticos (164.138.212.77).

#### Servidores de correo (MX)

| Dominio | Registro MX | Proveedor |
|---------|-------------|-----------|
| `grupo-gee.com` | `grupogee-com01c.mail.protection.outlook.com` (prio 0) | Microsoft 365 |
| `geelectromedico.com` | `geelectromedico-com.mail.protection.outlook.com` (prio 1) | Microsoft 365 |
| `ibermansa.com` | `ibermansa-com.mail.protection.outlook.com` (prio 1) | Microsoft 365 |
| `greelocal.com` | `greelocal-com.mail.protection.outlook.com` | Microsoft 365 |
| `iberdata.pt` | `iberdata-pt.mail.eo.outlook.com` (prio 0) | Microsoft 365 |

Las IPs de los MX resuelven al rango **52.96.0.0/12** (ASN 8075, Microsoft Corporation, Irlanda).

#### Registro SPF (TXT)

DNSDumpster muestra para `grupo-gee.com`:

```text
"v=spf1 include:spf.protection.outlook.com -all"
```

La política **-all** (hard fail) indica que solo los servidores autorizados de Outlook pueden enviar correo en nombre del dominio, dificultando el spoofing externo.

### Resultados y análisis

El correo del grupo está **centralizado en Microsoft 365**, lo que reduce la superficie de servidores SMTP propios expuestos, salvo registros legacy en `iberdata.pt` (195.23.128.0/24). La delegación DNS en GoDaddy implica dependencia de un proveedor global; los NS de GoDaddy serán objetivo de las pruebas de transferencia de zona y cache snooping en el apartado siguiente.

---

## 5. Testeo de vulnerabilidades (transferencia de zona y DNS Cache Snooping)

### Objetivo

Comprobar si los servidores DNS permiten transferencia de zona (AXFR) y si es posible realizar *cache snooping* para inferir dominios consultados recientemente.

### 5.1 Transferencia de zona (AXFR)

#### Procedimiento

`dnsenum` intenta automáticamente AXFR contra los NS descubiertos. Comandos de referencia adicionales:

```bash
dig @ns13.domaincontrol.com grupo-gee.com axfr
dig @ns1.puntumconsulting.com iberdata.pt axfr
dnsrecon -a -d grupo-gee.com
```

Evidencia en enumeración de `grupo-gee.com`:

![Intento de transferencia de zona en grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum.png)

#### Resultados

| Dominio | NS probado | Resultado AXFR |
|---------|-----------|----------------|
| `grupo-gee.com` | ns13, ns14.domaincontrol.com | `corrupt packet` |
| `geelectromedico.com` | ns13, ns14 | `corrupt packet` |
| `ibermansa.com` | ns55, ns56 | `corrupt packet` |
| `greelocal.com` | ns01, ns02 | `corrupt packet` |
| `iberdata.pt` | ns2.puntumconsulting.com | `REFUSED` |
| `iberdata.pt` | ns1.puntumconsulting.com | `Connection timed out` |

#### Análisis

En todos los casos la **transferencia de zona no es explotable**. GoDaddy y Puntum aplican controles que impiden divulgar el contenido completo de la zona a clientes no autorizados. Esto constituye una **buena práctica** de seguridad DNS.

---

### 5.2 DNS Cache Snooping

#### Procedimiento

Se utiliza el script NSE `dns-cache-snoop` de Nmap sobre servidores DNS identificados, consultando si dominios del grupo (y `google.com` como control) están en caché:

```bash
sudo nmap -sU -p 53 --script dns-cache-snoop.nse \
  --script-args 'dns-cache-snoop.domains={grupo-gee.com,geelectromedico.com,greelocal.com,ibermansa.com,iberdata.pt,google.com}' \
  97.74.106.7

sudo nmap -sU -p 53 --script dns-cache-snoop.nse \
  --script-args 'dns-cache-snoop.domains={grupo-gee.com,iberdata.pt,google.com}' \
  164.138.212.77
```

```bash
sudo nmap -sU -p 53 --script dns-cache-snoop.nse \
  --script-args 'dns-cache-snoop.domains={grupo-gee.com,geelectromedico.com,greelocal.com,ibermansa.com,iberdata.pt,google.com}' \
  97.74.100.1

sudo nmap -sU -p 53 --script dns-cache-snoop.nse \
  --script-args 'dns-cache-snoop.domains={grupo-gee.com,geelectromedico.com,greelocal.com,ibermansa.com,iberdata.pt,google.com}' \
  97.74.107.28
```

![DNS Cache Snooping en ns13 y servidor Puntum](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Cache%20Snooping%20con%20nmap.png)

![DNS Cache Snooping en ns01 y ns55](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Cache%20Snooping%20con%20nmap%202.png)

#### Resultados

| IP objetivo | Hostname | Dominios en caché | Ratio |
|-------------|----------|-------------------|-------|
| 97.74.106.7 | ns13.domaincontrol.com | `grupo-gee.com`, `geelectromedico.com` | 2/6 |
| 164.138.212.77 | servidor1.puntumconsulting.com | `grupo-gee.com`, `iberdata.pt` | 2/3 |
| 97.74.100.1 | ns01.domaincontrol.com | ninguno | 0/6 |
| 97.74.107.28 | ns55.domaincontrol.com | `ibermansa.com` | 1/6 |

#### Análisis

El **cache snooping** tuvo éxito parcial: algunos servidores DNS recursivos o autoritativos respondieron indicando que ciertos dominios del grupo estaban en caché, lo que puede revelar actividad reciente de resolución. Aunque el impacto directo es limitado, en un pentest real esta información ayuda a priorizar dominios activos.

**Recomendaciones** (según material de la unidad): restringir la recursión DNS a clientes autorizados, deshabilitar respuestas a consultas de terceros y monitorizar consultas anómalas al puerto 53/udp.

---

## 6. Obtención de rangos de IPs y nombres de redes (netnames)

### Objetivo

Determinar los bloques de direcciones IP (*inetnum*), nombres de red (*netname*) y sistemas autónomos (ASN) asociados a la infraestructura del grupo.

### Procedimiento

**Paso 1.** Consulta WHOIS sobre IPs clave:

```bash
whois 164.138.212.77
whois 97.74.106.7
whois -h whois.ripe.net 82.159.201.20
```

![WHOIS RIPE de 164.138.212.77 (Cyberneticos)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/whois%20164_138.png)

![WHOIS ARIN de 97.74.106.7 (GoDaddy)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/whois%2097_74.png)

**Paso 2.** Identificación de rangos /24 mediante `dnsenum` (sección *class C netranges*).

**Paso 3.** Correlación con DNSDumpster (ASN, RevIP, ubicación geográfica).

### Resultados

#### Netnames e inetnum (WHOIS)

| IP consultada | Netname | Inetnum / CIDR | ASN | Organización | País |
|---------------|---------|----------------|-----|--------------|------|
| 164.138.212.77 | CYBERNETICOS3 | 164.138.212.0 – 164.138.212.255 (/24) | AS198968 | Cyberneticos.com CPD | ES |
| 97.74.106.7 | GO-DADDY-COM-LLC | 97.74.0.0 – 97.74.255.255 (/16) | — | GoDaddy.com, LLC | US |
| MX Outlook | — | 52.96.0.0/12 | AS8075 | Microsoft Corporation | IE |

Contacto de abuso Cyberneticos: `abuse@cyberneticos.com`. Ruta BGP: `164.138.212.0/23`, origin AS198968.

#### Rangos /24 inferidos por dnsenum

| Dominio | Rangos identificados |
|---------|---------------------|
| `geelectromedico.com` | 82.159.201.0/24, 164.138.212.0/24 |
| `ibermansa.com` | 82.159.201.0/24, 82.223.212.0/24 |
| `greelocal.com` | 82.159.201.0/24, 82.159.203.0/24, 51.68.119.0/24, 91.142.211.0/24 |
| `iberdata.pt` | 164.138.212.0/24, 194.79.69.0/24, 195.23.128.0/24 |

El bloque **82.159.201.0/24** concentra la mayoría de subdominios internos (intranet, CRM, SSO, SFTP), constituyendo el segmento más sensible para fases posteriores de escaneo.

#### Resolución inversa

`dnsenum` ejecutó búsqueda inversa sobre 1024 IPs en los rangos de `greelocal.com` sin obtener PTR (`0 results out of 1024`), lo que limita el descubrimiento adicional por rDNS.

### Resultados y análisis

La infraestructura del grupo se distribuye entre:

1. **Hosting español** (Cyberneticos, AS198968) para presencia web principal.
2. **Rango 82.159.201.0/24** para aplicaciones internas y servicios de gestión.
3. **Servicios cloud** (Microsoft, Google, OVH, DigitalOcean/takeaspot) para correo, colaboración y reservas.

Esta segmentación orienta el plan de ataque: priorizar el escaneo de **82.159.201.0/24** y validar exposición de subdominios como `intranet.*`, `crm.*` y `adfs.*`.

---

## 7. Resumen y conclusiones

### Resumen de inteligencia recopilada

| Categoría | Hallazgos principales |
|-----------|----------------------|
| **Dominios / TLD** | 5+ dominios (.com y .pt); grupo empresarial multisite |
| **Subdominios** | >40 hosts; intranet, CRM, SSO, ADFS, oficina virtual, reservas |
| **NS** | GoDaddy (mayoría) y Puntum Consulting (iberdata.pt) |
| **MX** | Microsoft 365 centralizado; SPF hard fail en grupo-gee.com |
| **Vulnerabilidades DNS** | AXFR no explotable; cache snooping parcialmente exitoso |
| **Rangos IP** | 164.138.212.0/24, 82.159.201.0/24, 82.223.212.0/24, 195.23.128.0/24 |

### Conclusiones

El reconocimiento DNS sobre **Grupo GEE** ha permitido cartografiar la superficie de ataque del grupo sin necesidad de acceso interno. Las técnicas pasivas (DNSDumpster) y activas (`dnsenum`, `dig`, `nmap` NSE, recon-ng) se complementan: las primeras aportan contexto y banners; las segundas descubren subdominios no indexados públicamente.

**Aspectos positivos de la postura del objetivo:**

- Transferencia de zona **deshabilitada** en todos los NS probados.
- Correo protegido por **Microsoft 365** con registro **SPF -all**.
- Separación parcial entre web pública (164.138.212.x) y servicios internos (82.159.201.x).

**Riesgos e inteligencia para fases posteriores:**

- Subdominios de **intranet**, **CRM**, **SFTP** y **ADFS** accesibles desde Internet.
- **Cache snooping** exitoso en ns13.domaincontrol.com y servidor Puntum, indicando resolución reciente de dominios del grupo.
- **Hosting compartido** (RevIP 413 en 164.138.212.77) con posible riesgo de vecindad.
- Servicios en **terceros** (Google, takeaspot.net, OVH) que amplían la superficie fuera del control directo del grupo.

### Estrategia recomendada para siguientes fases

1. **Escaneo de puertos** (`nmap`) sobre 82.159.201.0/24 y subdominios críticos detectados.
2. **Enumeración por certificados** (`ct-exposer` o crt.sh) para descubrir subdominios adicionales.
3. **Análisis web** de `intranet.*`, `crm.*`, `oficinavirtual.*` (tecnologías, autenticación, versiones).
4. **Verificación de correo** (registros DKIM/DMARC complementarios a SPF).
5. **Monitorización** de intentos de cache snooping y recursión DNS abierta en servidores propios.

---

*Informe elaborado como evidencia de la práctica «Reconocimiento DNS de una empresa». Todas las capturas referenciadas se encuentran en el repositorio [GEE_OSINT](https://github.com/alejandroquinonesgamez/GEE_OSINT), carpeta `Capturas/OSINT/`.*
