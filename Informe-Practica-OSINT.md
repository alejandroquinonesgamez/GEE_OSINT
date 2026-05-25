# Reconocimiento DNS de una empresa

**Autor:** Alejandro Quiñones Gámez  
**Asignatura:** Hacking Ético  
**Curso:** Especialización en Ciberseguridad en Tecnologías de la Información

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

La presente práctica aplica técnicas de reconocimiento DNS sobre **Grupo GEE**, grupo empresarial del sector electromédico y servicios asociados, con presencia en varios dominios y TLD. El trabajo se ejecuta desde **Kali Linux** y desarrolla los [apartados 1 a 8](#alcance-y-estructura-del-informe) recogidos en este mismo informe.

Herramientas empleadas: `dig`, `dnsenum`, `whois`, `nmap` (script NSE `dns-cache-snoop`), **recon-ng** (módulo Hackertarget), **DNSDumpster**, **Sublist3r**, **theHarvester**, **Google Dorks**, **Hunter.io**, **Have I Been Pwned** y **ExifTool** (análisis de metadatos en documentos PDF públicos).

<a id="alcance-y-estructura-del-informe"></a>

### Alcance y estructura del informe

**Título de la práctica:** Reconocimiento DNS de una empresa.

**Objetivo:** Poner en práctica técnicas de reconocimiento de la infraestructura DNS sobre un objetivo de elección, preferentemente una **empresa de tamaño mediano-grande** con información suficiente para el reconocimiento, y elaborar un resumen de recursos que permita planificar las fases siguientes del test de intrusión.

**Enfoque:** Técnicas **pasivas** (sin rastro identificable en el objetivo) y **activas** (consultas DNS registrables), en la fase de descubrimiento o *footprinting*.

**Estructura obligatoria** (contenido en los apartados siguientes de este documento):

| Apartado | Sección del informe |
|----------|---------------------|
| 1 | [Descripción del objetivo](#apartado-1) |
| 2 | [Obtención de dominios TLD](#apartado-2) |
| 3 | [Obtención de subdominios](#apartado-3) |
| 4 | [Obtención de NS y MX](#apartado-4) |
| 5 | [Testeo de vulnerabilidades DNS](#apartado-5) |
| 6 | [Obtención de rangos IP y netnames](#apartado-6) |
| 7 | [Reconocimiento pasivo complementario OSINT](#apartado-7) |
| 8 | [Resumen y conclusiones](#apartado-8) |

---

<a id="apartado-1"></a>

## 1. Descripción del objetivo

### Objetivo

Identificar y caracterizar la organización seleccionada como blanco de reconocimiento, justificando su idoneidad para un ejercicio de enumeración DNS.

### Presentación del objetivo

Para esta práctica se analiza **GEE** (*Grupo Empresarial Electromédico*), organización en la que el autor desarrolla su actividad profesional. El grupo se presenta públicamente como especialista en **electromedicina e ingeniería sanitaria**, con presencia internacional. El dominio principal expuesto en Internet es **`grupo-gee.com`**, aunque la huella digital real se distribuye entre dominios históricos, filiales y servicios corporativos asociados.

### Criterios de idoneidad

El blanco debe ser una **empresa de tamaño mediano-grande** con información suficiente para el reconocimiento DNS (véase [Alcance y estructura](#alcance-y-estructura-del-informe)). GEE cumple ese perfil: **múltiples dominios y subdominios**, **servicios expuestos** (web, correo, oficina virtual), **infraestructura en varios proveedores** (GoDaddy, Puntum, Microsoft 365) y **rangos consultables en RIR**. El análisis DNS activo complementa la OSINT pasiva y cubre los apartados del [2](#apartado-2) al [6](#apartado-6) de este informe.

### Información general de la empresa (OSINT)

La fase inicial de OSINT muestra que GEE **no opera como una única entidad monolítica**, sino como un **conglomerado corporativo**:

- **Núcleo del grupo:** **MANTELEC, S.A.**, **ASIME, S.A.** e **IBERMAN, S.A.** (esta última asociada al dominio `ibermansa.com`), con actividad transversal a nivel nacional y participación habitual en licitaciones públicas, a menudo en **Uniones Temporales de Empresas (UTE)**.
- **Filiales territoriales:** por ejemplo **Euskalman S.L.** (País Vasco), sin dominio público propio identificado en esta fase.
- **Presencia internacional:** delegaciones y marcas como **Ibermansa** (LATAM), **ITH Maroc** (Norte de África) o **Iberdata** (Portugal), con distintos grados de exposición web (dominios propios, rutas bajo `grupo-gee.com` o ausencia de DNS dedicado).

### Justificación del alcance

Desde el punto de vista de inteligencia para un test de intrusión, estas sociedades deben incluirse en el reconocimiento porque pueden **compartir infraestructura, correo, accesos remotos, proveedores DNS, certificados TLS o servicios corporativos centralizados**. Ello es especialmente relevante en un grupo que concurre a licitaciones públicas y opera de forma coordinada en varias comunidades autónomas y mercados exteriores.

Los dominios con actividad DNS verificada en el laboratorio son:

| Dominio | Rol inferido |
|---------|----------------|
| `grupo-gee.com` | Dominio corporativo principal (actual) |
| `geelectromedico.com` | Dominio corporativo histórico / electromédico |
| `ibermansa.com` | IBERMAN S.A. — gestión, CRM, intranet |
| `greelocal.com` | Oficina virtual, formación y acceso remoto |
| `iberdata.pt` | Filial Portugal (ccTLD `.pt`) |

La infraestructura observada combina hosting en España (**Cyberneticos**, Cádiz), delegación DNS en **GoDaddy** o **Puntum Consulting**, y correo en **Microsoft 365** (*mail.protection.outlook.com*).

### Procedimiento

Se inicia el reconocimiento pasivo con la herramienta web **DNSDumpster**, introduciendo el dominio raíz `grupo-gee.com` como punto de partida del análisis.

En la siguiente captura se muestra la **primera consulta en DNSDumpster** sobre `grupo-gee.com`, utilizada para obtener de forma pasiva un mapa inicial de registros DNS (A, NS, MX) sin interactuar con los servidores autoritativos del objetivo mediante herramientas de línea de comandos.

![Consulta inicial en DNSDumpster para grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster.png)

**Paso 2.** Búsqueda pasiva con operadores avanzados de Google para perfilar la organización y localizar activos web:

```text
site:grupo-gee.com OR site:geelectromedico.com "@geelectromedico.com"
```

En la captura siguiente aparece la ejecución del **Google Dork** anterior en el buscador. El operador `site:` limita los resultados a los dominios del grupo y `"@geelectromedico.com"` fuerza la aparición de direcciones de correo indexadas.

**Marcas en la captura:** el **recuadro rojo** señala la consulta exacta introducida en la barra de búsqueda; el **subrayado rojo** en un resultado destaca el correo `informacion@geelectromedico.com`, confirmando que el dork localiza contactos corporativos expuestos en la web pública.

![Google Dorks: emails y rutas web del grupo](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/google_dorks.png)

Se obtiene el correo `informacion@geelectromedico.com`, el teléfono **+34 91 549 14 07**, la dirección en **San Sebastián de los Reyes (Madrid)** —Avda. Tenerife, 2, Complejo Empresarial MARPE— y rutas como `/wp-content/uploads/` (indicio de **WordPress** en `geelectromedico.com`).

**Paso 3.** Localización de documentos PDF corporativos indexados:

```text
site:grupo-gee.com filetype:pdf
```

La siguiente captura muestra el resultado de `site:grupo-gee.com filetype:pdf`, empleado para localizar **documentos PDF corporativos** indexados por Google (políticas, códigos de conducta, certificados) que luego se analizan con ExifTool en el [apartado 6](#apartado-6).

![Google Dorks: documentos PDF en grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/google_dorks_pdf.png)

Entre los ficheros públicos figuran el *Código de conducta* y la *política integrada GEE*, que permiten identificar filiales (**MANTELEC, S.A.**) y otra sede en **Tudela (Navarra)**.

**Paso 4.** Revisión del documento *Código de conducta* (GEE-D-RSC-01), descargado desde la web del grupo:

En la imagen se muestra la **portada del PDF** descargado, como evidencia de que el fichero identificado en el dork es accesible y corresponde a documentación oficial del grupo (referencia GEE-D-RSC-01).

![Portada del Código de conducta GEE](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/pdf.png)

El documento confirma que el **Grupo Empresarial Electromédico (GEE)** —fundado en 1982— integra las sociedades **MANTELEC, S.A.**, **IBERMAN, S.A.** y **ASIME, S.A.**, lo que explica dominios como `ibermansa.com` y `asimesa.com` en el reconocimiento posterior.

### Resultados y análisis

Grupo GEE cumple los requisitos del [apartado 1](#apartado-1): es una organización con múltiples dominios, subdominios publicados, servidores NS/MX diferenciados y rangos de IP consultables en RIR. La diversidad de TLD (`.com`, `.pt`) y de proveedores DNS facilita comparar configuraciones y detectar posibles debilidades (transferencia de zona, cache snooping), abordadas en el [apartado 5](#apartado-5).

---

<a id="apartado-2"></a>

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
theharvester -d ibermansa.com -l 500 -b duckduckgo,yahoo
theharvester -d iberdata.pt -l 500 -b duckduckgo,yahoo
```

La captura recoge la salida de **`theharvester`** sobre varios dominios del grupo. Esta herramienta agrega correos, hosts y metadatos desde buscadores (DuckDuckGo, Yahoo) de forma pasiva, para contrastar dominios activos antes de la enumeración DNS activa.

![Resultados de theHarvester sobre dominios del grupo](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/harvester.png)

**Paso 2.** Análisis de resolución DNS inicial con `dnsenum` sin diccionario sobre el dominio corporativo:

```bash
dnsenum grupo-gee.com
```

En la siguiente imagen se observa la ejecución de **`dnsenum grupo-gee.com`** (sin diccionario), que resuelve la IP del host, enumera **NS y MX** e intenta **transferencia de zona (AXFR)** contra los servidores GoDaddy.

**Marcas en la captura:** el **recuadro rojo** enmarca el comando lanzado; el resto de la salida muestra la IP **164.138.212.77**, los NS `ns13`/`ns14.domaincontrol.com`, los MX de Microsoft 365 y el fallo de AXFR (`corrupt packet`), coherente con una zona no transferible.

![Enumeración DNS básica de grupo-gee.com con dnsenum](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum.png)

**Paso 3.** Enumeración de TLD alternativos con `dnsrecon` (base del nombre sin TLD):

```bash
dnsrecon -t tld -d grupo-gee
```

La enumeración TLD tarda varios minutos (estimación inicial ~56 min) y genera **5213 registros** en la salida bruta; la mayoría son **falsos positivos** (p. ej. `grupo-gee.s3.amazonaws.com`, `grupo-gee.yolasite.com`, `grupo-gee.lib.ee` → `127.0.0.1`). Para el análisis se conservan solo los TLD con nombre `grupo-gee.<tld>` y resolución coherente (extracto en `Capturas/OSINT/dnsrecon_tld_grupo-gee.txt`: **12 registros**).

**Captura 1 — inicio del escaneo.** Muestra el arranque de `dnsrecon -t tld -d grupo-gee`: tiempo estimado de ejecución y los primeros registros A/AAAA hallados (p. ej. `grupo-gee.com`, `.es`, `.net`), mezclados con muchos falsos positivos de TLD de terceros.

**Marcas en la captura:** el **recuadro rojo** señala el comando ejecutado; sirve de evidencia del inicio de la prueba TLD descrita en el [apartado 2](#apartado-2).

![Inicio de dnsrecon -t tld -d grupo-gee (comando y primeros A/AAAA)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsrecon_tld_grupo-gee.png)

**Captura 2 — cierre del escaneo.** Corresponde al final de la misma ejecución, cuando la herramienta reporta el total de coincidencias.

**Marcas en la captura:** el **recuadro rojo** enmarca la línea **«5213 Records Found»** y el mensaje *Completed enumeration for domain: grupo-gee*; ese volumen justifica filtrar la salida y no incorporar el log completo al informe, usando solo el extracto de 12 dominios relevantes.

![Fin de la enumeración TLD: 5213 Records Found](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsrecon_tld_grupo-gee_2.png)

**Dominios filtrados (12 registros A relevantes):**

| Dominio encontrado | IP (A) | Relevancia |
|--------------------|--------|------------|
| `grupo-gee.com` | 164.138.212.77 | Dominio corporativo activo |
| `grupo-gee.net` | 15.197.225.128 / 3.33.251.168 | gTLD alternativo / posible parking |
| `grupo-gee.es` | 15.197.148.33 / 3.33.130.190 | ccTLD España; verificar titularidad |
| `grupo-gee.ph` | 45.79.222.138 | ccTLD Filipinas |
| `grupo-gee.ac.jobs` | 64.190.63.222 | gTLD genérico |
| `grupo-gee.vg` | 88.198.29.97 | ccTLD Islas Vírgenes |
| `grupo-gee.be.biz` | 13.248.169.48 / 76.223.54.146 | ccTLD Bélgica |
| `grupo-gee.bg.com` | 13.225.61.36 | ccTLD Bulgaria |
| `grupo-gee.ws` | 64.70.19.203 | ccTLD Samoa |

**Conclusión del apartado:** el grupo mantiene presencia DNS bajo el nombre base `grupo-gee` en varios TLD; el activo operativo principal sigue siendo **`grupo-gee.com`** (164.138.212.77, mismo bloque que la web corporativa). El resto de TLD detectados conviene verificarlos en WHOIS/RDAP antes de ampliar el alcance del pentest.

### Inventario ampliado de dominios y presencia web

A partir del análisis pasivo (documentación corporativa, web pública y resolución DNS), se construye el inventario del conglomerado ya descrito en el [apartado 1](#apartado-1):

| Entidad / servicio | Rol | Dominio o URL pública | Observaciones |
|--------------------|-----|------------------------|---------------|
| Grupo Empresarial Electromédico | Corporativo principal (actual) | `grupo-gee.com` | A → 164.138.212.77; NS GoDaddy |
| Grupo Empresarial Electromédico | Corporativo principal (antiguo) | `geelectromedico.com` | Misma IP web; legado de marca |
| Oficina virtual | Servicio de acceso remoto | `https://oficinavirtual.greelocal.com/Account/LogIn` | Panel de autenticación expuesto |
| MANTELEC, S.A. | Núcleo del grupo | Sin dominio público propio | Citada en PDF corporativos |
| ASIME, S.A. | Núcleo del grupo | `asimesa.com` (relacionado) | Sin resolución útil en theHarvester |
| IBERMAN, S.A. | Núcleo del grupo | `ibermansa.com` | A → 82.223.212.16; servicios en 82.159.201.0/24 |
| Euskalman S.L. | Filial País Vasco | Sin dominio público propio | Solo referencia organizativa |
| Iberdata | Filial Portugal | `iberdata.pt` | ccTLD; NS Puntum Consulting |
| Ibermansa Perú | Filial LATAM | `geelectromedico.com/ibermansa-peru/` | Ruta bajo dominio histórico, no FQDN propio |
| Ibermansa Chile | Filial LATAM | Sin dominio público propio | — |
| Ibermansa Ghana | Filial África | `grupo-gee.com/en/ibermansa-ghana/` | Contenido bajo web corporativa |
| ITH Maroc | Filial Marruecos | Sin dominio público propio | — |
| greelocal.com | Plataformas internas | `greelocal.com` | NS GoDaddy; MX Microsoft 365 |

**Nota organizativa:** según la documentación interna del grupo, una **reestructuración reciente** ha dejado **dominios obsoletos** y **nuevos activos aún en despliegue**, lo que explica coexistencia de `grupo-gee.com` y `geelectromedico.com` y la heterogeneidad de filiales con o sin DNS dedicado.

### Resultados técnicos (resolución DNS)

| Dominio | TLD | Tipo | IP principal (A) | Proveedor DNS (NS) |
|---------|-----|------|------------------|---------------------|
| `grupo-gee.com` | `.com` | gTLD | 164.138.212.77 | GoDaddy (domaincontrol.com) |
| `geelectromedico.com` | `.com` | gTLD | 164.138.212.77 | GoDaddy |
| `ibermansa.com` | `.com` | gTLD | 82.223.212.16 | GoDaddy |
| `greelocal.com` | `.com` | gTLD | — | GoDaddy (NS `ns13`/`ns14`) |
| `iberdata.pt` | `.pt` | ccTLD | 164.138.212.77 | Puntum Consulting |
| `asimesa.com` | `.com` | gTLD | — | Filial ASIME (sin hosts en theHarvester) |

En `geelectromedico.com`, theHarvester identificó `informacion@geelectromedico.com` y `talento@geelectromedico.com`, alineados con Google Dorks y Hunter.io ([apartado 7](#apartado-7)).

### Resultados y análisis

El grupo opera principalmente bajo **gTLD `.com`**, con **`iberdata.pt`** como **ccTLD** para Portugal. La IP **164.138.212.77** concentra la web corporativa (Cyberneticos); **`ibermansa.com`** y **`greelocal.com`** despliegan aplicaciones en **82.159.201.0/24**. El inventario de este [apartado 2](#apartado-2) refuerza que el alcance no debe limitarse a un solo FQDN, sino al **ecosistema de filiales y servicios compartidos**.

---

<a id="apartado-3"></a>

## 3. Obtención de subdominios

### Objetivo

Descubrir nombres de host y subdominios públicos del grupo mediante técnicas activas (fuerza bruta DNS, consultas a APIs) y pasivas (DNSDumpster, Hackertarget).

### Procedimiento

#### Paso 1. Enumeración con dnsenum y diccionario

Se emplea el diccionario `Capturas/OSINT/mini_dict.txt` (~5000 entradas) con `dnsenum`. Sobre el dominio raíz `grupo-gee.com` el brute force aporta subdominios adicionales (`www`, `autodiscover`) y búsqueda inversa en el /24 de Cyberneticos:

```bash
dnsenum grupo-gee.com -f Capturas/OSINT/mini_dict.txt
```

Complementar con consultas manuales sobre hosts descubiertos:

```bash
dig www.grupo-gee.com A +short
dig autodiscover.grupo-gee.com A +short
```

La siguiente captura documenta **`dnsenum grupo-gee.com -f Capturas/OSINT/mini_dict.txt`**: fuerza bruta de subdominios con diccionario (~5000 entradas), descubrimiento de `www` y `autodiscover`, e inferencia del /24 **164.138.212.0/24** (Cyberneticos).

![Brute force DNS sobre grupo-gee.com con mini_dict.txt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20Dict.png)

Se repite el procedimiento sobre el resto de dominios del grupo:

```bash
dnsenum geelectromedico.com -f Capturas/OSINT/mini_dict.txt
dnsenum greelocal.com -f Capturas/OSINT/mini_dict.txt
dnsenum iberdata.pt -f Capturas/OSINT/mini_dict.txt
dnsenum ibermansa.com -f Capturas/OSINT/mini_dict.txt
```

**`geelectromedico.com`.** Salida de `dnsenum` con diccionario: subdominios de correo (`smtp`, `webmail`), integración Google Workspace y Microsoft 365, y rangos en **82.159.201.0/24** y **164.138.212.0/24**.

![Brute force DNS sobre geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20geelectromedico.png)

**`greelocal.com`.** Misma metodología; destaca la concentración de servicios internos (`sso`, `adfs`, `oficinavirtual`, `sftp`, `aulavirtual`) en el bloque **82.159.201.0/24**, clave para el alcance del pentest.

![Brute force DNS sobre greelocal.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20greelocal.png)

**`iberdata.pt`.** Enumeración con NS en Puntum Consulting; confirma hosting en **164.138.212.77** y rangos adicionales portugueses.

![Brute force DNS sobre iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20iberdata.png)

**`ibermansa.com`.** Descubre `intranet`, `crm`, `webmail` y subdominios en **82.159.201.0/24** y **82.223.212.0/24**, alineados con IBERMAN S.A.

![Brute force DNS sobre ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dnsenum%20Iberman.png)

#### Paso 2. Reconocimiento con recon-ng (Hackertarget)

Se configura **recon-ng** con workspace `gee`, prueba del módulo Bing (sin resultados) e instalación del módulo **Hackertarget** para consulta pasiva de hosts.

```bash
recon-ng -w gee
workspaces create gee
marketplace install recon/domains-hosts/bing_domain_web
modules load recon/domains-hosts/bing_domain_web
options set SOURCE grupo-gee.com
run
marketplace install recon/domains-hosts/hackertarget
modules load recon/domains-hosts/hackertarget
options set SOURCE grupo-gee.com
run
# Repetir cambiando SOURCE para ibermansa.com, iberdata.pt, geelectromedico.com, greelocal.com
show hosts
```

La primera captura muestra la ejecución del módulo **`recon/domains-hosts/hackertarget`** en **recon-ng** sobre `grupo-gee.com`, consultando la API de Hackertarget para listar subdominios sin fuerza bruta local.

![Módulo Hackertarget sobre grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Hacertarget%20grupo-gee.png)

La segunda captura presenta el resultado de **`show hosts`** en el workspace `gee`, con los FQDN consolidados de todos los dominios cargados (grupo-gee, ibermansa, iberdata, geelectromedico, greelocal).

![Hosts consolidados en workspace gee](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Hackertarget%20all.png)

#### Paso 3. Sublist3r (enumeración pasiva multi-fuente)

```bash
sublist3r -d grupo-gee.com
```

La captura documenta un intento de **`sublist3r -d grupo-gee.com`** (fuentes pasivas como VirusTotal). La ejecución **falló** por error de API; se deja como evidencia negativa y las fuentes restantes cubren el descubrimiento de subdominios.

![Intento de enumeración con Sublist3r (error)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Sublist3r.png)

#### Paso 4. DNSDumpster (reconocimiento pasivo)

Consultas en https://dnsdumpster.com para cada dominio principal. Por cada dominio se conservan tres vistas: **mapa general**, **tabla de registros** y **grafo de relaciones** (hosts, NS, MX y enlaces entre nodos).

**Dominio `grupo-gee.com`**

- *Mapa:* vista global de la zona y proveedores.
- *Detalle:* registros A, NS, MX y TXT (incl. SPF).
- *Grafo:* relaciones entre hosts y servicios.

![Mapa DNS de grupo-gee.com en DNSDumpster](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20grupo-gee1.png)

![Detalle de registros grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20grupo-gee2.png)

![Grafo de relaciones DNS grupo-gee.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20grupo-gee-grafo.png)

**Dominio `geelectromedico.com`** — misma secuencia (mapa, detalle, grafo) para el dominio histórico del grupo.

![Mapa DNS geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20geelectromedico1.png)

![Detalle geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20geelectromedico2.png)

![Grafo geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20geelectromedico_grafo.png)

**Dominio `ibermansa.com`** — expone subdominios de intranet/CRM y rangos en 82.159.x.

![Mapa DNS ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20ibermansa1.png)

![Detalle ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20ibermansa2.png)

![Grafo ibermansa.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20ibermansa_grafo.png)

**Dominio `iberdata.pt`** — NS en Puntum Consulting y correlación con hosting español/portugués.

![Mapa DNS iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20iberdata1.png)

![Detalle iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20iberdata2.png)

![Grafo iberdata.pt](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/DNSDumpster%20iberdata_grafo.png)

### Tabla resumen de subdominios identificados

#### grupo-gee.com

| Subdominio | IP / destino | Servicio inferido |
|------------|--------------|-------------------|
| `www.grupo-gee.com` | 164.138.212.77 | Web corporativa (dnsenum + diccionario) |
| `autodiscover.grupo-gee.com` | Microsoft 365 (CNAME) | Autodiscover Outlook |

#### geelectromedico.com

| Subdominio | IP / destino | Servicio inferido |
|------------|--------------|-------------------|
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

<a id="apartado-4"></a>

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

La captura agrupa la salida de los comandos **`dig ns … +short`** y **`dig mx … +short`** sobre los cuatro dominios principales. Permite comparar de un vistazo la delegación DNS (GoDaddy vs Puntum) y la centralización del correo en **Microsoft 365**.

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

<a id="apartado-5"></a>

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

Evidencia en enumeración de `grupo-gee.com` (misma salida que en el [apartado 2](#apartado-2)): `dnsenum` intenta AXFR automáticamente contra los NS de GoDaddy. La captura evidencia el **recuadro rojo** con el comando y los mensajes `AXFR record query failed: corrupt packet`.

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

**Captura 1 — ns13 (GoDaddy) y Puntum.** Ejecución de `nmap` con el script **`dns-cache-snoop.nse`** sobre **97.74.106.7** (`ns13.domaincontrol.com`) y **164.138.212.77** (`servidor1.puntumconsulting.com`).

**Marcas en la captura:** los **subrayados rojos** señalan la lista de dominios probados y la IP objetivo de cada comando; los **recuadros rojos** enmarcan el resultado *«N domains are cached»* (2/6 y 2/3), indicando que `grupo-gee.com`, `geelectromedico.com` e `iberdata.pt` estaban en caché en esos resolvers.

![DNS Cache Snooping en ns13 y servidor Puntum](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/Cache%20Snooping%20con%20nmap.png)

**Captura 2 — ns01 y ns55.** Misma prueba sobre **97.74.100.1** (sin dominios en caché) y **97.74.107.28** (caché de `ibermansa.com`), completando el barrido de NS GoDaddy del grupo.

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

**Recomendaciones:** restringir la recursión DNS a clientes autorizados, deshabilitar respuestas a consultas de terceros y monitorizar consultas anómalas al puerto 53/udp.

### Resultados y análisis (vulnerabilidades DNS)

La **transferencia de zona** no es explotable en ningún NS probado (GoDaddy y Puntum). El **cache snooping** obtuvo resultados parciales en `97.74.106.7`, `164.138.212.77` y `97.74.107.28`, lo que puede indicar resolución reciente de dominios del grupo en esos resolvers. La configuración AXFR es adecuada; el riesgo residual está en la filtración de actividad vía caché DNS, no en la divulgación masiva de zonas.

Comando adicional de confirmación AXFR:

```bash
dig @ns13.domaincontrol.com grupo-gee.com axfr
```

La captura muestra la confirmación manual con **`dig @ns13.domaincontrol.com grupo-gee.com axfr`**: errores de comunicación y *no servers could be reached* / cierre de sesión, coherente con **AXFR no permitido** frente a consultas no autorizadas.

![Transferencia de zona (AXFR) sobre grupo-gee.com — REFUSED](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/dig_axfr_grupo-gee.png)

---

<a id="apartado-6"></a>

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

**IP 164.138.212.77 (web corporativa).** Salida de `whois` en RIPE: bloque **164.138.212.0/24**, netname **CYBERNETICOS3**, ASN **AS198968**, organización **Cyberneticos.com CPD** (España).

![WHOIS RIPE de 164.138.212.77 (Cyberneticos)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/whois%20164_138.png)

**IP 82.159.201.20 (greelocal / SSO).** Consulta `whois -h whois.ripe.net 82.159.201.20` sobre el host usado por subdominios internos; primera pantalla con **inetnum 82.159.0.0–82.159.255.255**, netname **ES-ONO-20031202** y titular **VODAFONE ONO, S.A.**

![WHOIS RIPE de 82.159.201.20 (Vodafone ONO, netname ES-ONO-20031202)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/whois%2082_159_201_1.png)

**Continuación WHOIS 82.159.201.20.** Segunda captura con datos de contacto, rol *VODAFONE IP MANAGER* y buzón de abuso `abuse@corp.vodafone.es`, útiles para el informe de red y correlación con PTR `greeperi01.greelocal.com`.

![WHOIS RIPE de 82.159.201.20 (continuación: ruta, abuse)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/whois%2082_159_201_2.png)

**IP 97.74.106.7 (NS GoDaddy).** `whois` vía ARIN: bloque **97.74.0.0/16**, organización **GoDaddy.com, LLC** (Estados Unidos), coherente con `ns13.domaincontrol.com`.

![WHOIS ARIN de 97.74.106.7 (GoDaddy)](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/whois%2097_74.png)

**Paso 2.** Identificación de rangos /24 mediante `dnsenum` (sección *class C netranges*).

**Paso 3.** Correlación con DNSDumpster (ASN, RevIP, ubicación geográfica).

**Paso 4.** Análisis de metadatos en PDFs descubiertos con `exiftool`, para extraer nombres internos de sistemas y rutas de red:

```bash
exiftool Capturas/OSINT/CODIGO_DE_CONDUCTA.pdf
exiftool Capturas/OSINT/ENS-FR05-231228-Certificado-ENS-FIRMADO.pdf
exiftool Capturas/OSINT/GEE-P-SGI-01-POLITICA-GEE.pdf
```

**PDF *Código de conducta*.** Salida de **`exiftool Capturas/OSINT/CODIGO_DE_CONDUCTA.pdf`** para extraer metadatos embebidos (software, fechas, rutas internas).

**Marcas en la captura:** el **recuadro superior** muestra el comando ejecutado; los **subrayados rojos** destacan (1) fechas de edición en *History When* (2021), (2) agente **Adobe Illustrator 25.0 (Windows)** y (3) la ruta UNC **`\\greedatos\DEPARTAMENTOS\Dpto. Marketing\...`**, que revela nombre de servidor de ficheros y estructura interna.

![Metadatos del Código de conducta: rutas UNC internas](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/pdf_carving.png)

**PDFs ENS y política SGI.** Segunda captura con metadatos de los documentos de cumplimiento (autor «Idoia», Microsoft Word 365, impresora *Develop ineo+ 450i*), que aportan perfil tecnológico de puestos de trabajo.

![Metadatos de certificado ENS y política SGI](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/pdf_carving_2.png)

### Resultados

#### Netnames e inetnum (WHOIS)

| IP consultada | Netname | Inetnum / CIDR | ASN | Organización | País |
|---------------|---------|----------------|-----|--------------|------|
| 164.138.212.77 | CYBERNETICOS3 | 164.138.212.0 – 164.138.212.255 (/24) | AS198968 | Cyberneticos.com CPD | ES |
| 82.159.201.20 | ES-ONO-20031202 | 82.159.0.0 – 82.159.255.255 (/16) | AS6739 | VODAFONE ONO, S.A. | ES |
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

```bash
host -t ptr 82.159.201.20
host -t ptr 164.138.212.77
```

| IP | PTR (nombre inverso) |
|----|----------------------|
| 82.159.201.20 | `greeperi01.greelocal.com` |
| 164.138.212.77 | `servidor1.puntumconsulting.com` |

El PTR de **82.159.201.20** confirma el vínculo entre la red **Vodafone ONo** y la plataforma **greelocal.com** (`greeperi01`). `dnsenum` ejecutó además búsqueda inversa masiva sobre 1024 IPs en rangos de `greelocal.com` y el /24 `164.138.212.0/24` sin PTR adicionales (`0 results`).

La captura muestra la ejecución de **`host -t ptr`** sobre **82.159.201.20** y **164.138.212.77**, comandos de resolución inversa que confirman los nombres `greeperi01.greelocal.com` y `servidor1.puntumconsulting.com` respectivamente.

![Resolución inversa PTR de 82.159.201.20 → greeperi01.greelocal.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/host_ptr_interno.png)

#### Infraestructura interna revelada por metadatos PDF

| Fichero | Dato relevante | Implicación |
|---------|----------------|-------------|
| `CODIGO_DE_CONDUCTA.pdf` | Ruta UNC `\\greedatos\DEPARTAMENTOS\Dpto. Marketing\...` | Nombre de servidor de ficheros interno (**greedatos**) |
| `CODIGO_DE_CONDUCTA.pdf` | Adobe Illustrator 25.0 (Windows), fechas 2021–2022 | Perfil de estaciones de trabajo |
| `ENS-FR05-231228-Certificado-ENS-FIRMADO.pdf` | Autor «Idoia», Microsoft Word 365 | Usuario y suite ofimática |
| `GEE-P-SGI-01-POLITICA-GEE.pdf` | Impresora **Develop ineo+ 450i** | Modelo de hardware de oficina |

El hostname **greedatos** guarda relación semántica con `greelocal.com` y refuerza la hipótesis de un entorno Windows/File Server interno asociado al grupo.

### Resultados y análisis

La infraestructura del grupo se distribuye entre:

1. **Hosting español** (Cyberneticos, AS198968) para presencia web principal.
2. **Rango 82.159.201.0/24** para aplicaciones internas y servicios de gestión.
3. **Servicios cloud** (Microsoft, Google, OVH, DigitalOcean/takeaspot) para correo, colaboración y reservas.

Esta segmentación orienta el plan de ataque: priorizar el escaneo de **82.159.201.0/24** y validar exposición de subdominios como `intranet.*`, `crm.*` y `adfs.*`.

---

<a id="apartado-7"></a>

## 7. Reconocimiento pasivo complementario (OSINT)

### Objetivo

Complementar el reconocimiento DNS de los [apartados 1 a 6](#apartado-1) con técnicas pasivas adicionales que alimentan la inteligencia sobre personas, correos, documentos y posibles vectores de ataque vinculados a los dominios ya identificados.

### 7.1 Perfiles profesionales (Google Dorks + LinkedIn)

```text
site:es.linkedin.com/in/ "Grupo Empresarial Electromédico"
```

En la siguiente captura se aplica el dork anterior para localizar **perfiles de LinkedIn** vinculados al grupo; es reconocimiento pasivo de personas sin contactar con la infraestructura DNS del objetivo.

![Google Dorks: empleados en LinkedIn](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/google_dorks_ppl.png)

Se localizan perfiles con cargos relevantes (p. ej. **Director General**, gestores de proyecto en electromedicina, personal técnico en Madrid y Málaga). Esta información complementa la enumeración DNS al identificar posibles objetivos de ingeniería social o spear phishing.

### 7.2 Correos corporativos (Hunter.io)

Consulta en [Hunter.io](https://hunter.io) sobre `geelectromedico.com` y dominios relacionados:

La captura muestra la búsqueda en **Hunter.io** filtrando dominios del conglomerado (`geelectromedico.com`, `ibermansa.com`, `iberdata.com`, `grupo-gee.com`), con el fin de obtener correos corporativos y roles por departamento.

**Marcas en la captura:** los **recuadros rojos** señalan (1) la herramienta Hunter, (2) el bloque de **empresas relacionadas** (GEE, Ibermansa, IberData), (3) el recuento de **39 correos** en el dominio principal y (4) la lista por departamentos, donde destaca el perfil de **administrador de infraestructura (IT)** como objetivo de alto valor en un pentest.

![Hunter.io: 39 correos y estructura por departamentos](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/hunter_io.png)

Hunter.io reporta **39 direcciones** en `geelectromedico.com`, clasificadas en personas, decisores y cuentas genéricas. Destaca personal de **IT** (administrador de infraestructura), **ventas**, **soporte** y **dirección regional**, coherente con la sede en San Sebastián de los Reyes. Los dominios `ibermansa.com` e `iberdata.com` aparecen como asociados en la misma búsqueda.

### 7.3 Comprobación de filtraciones (Have I Been Pwned)

Sobre el correo `talento@geelectromedico.com` (RR. HH., también hallado por theHarvester):

La imagen documenta la consulta en **Have I Been Pwned** sobre `talento@geelectromedico.com`, para comprobar si esa cuenta aparece en filtraciones públicas conocidas (vector habitual de reutilización de credenciales).

![Have I Been Pwned: sin brechas para talento@geelectromedico.com](https://raw.githubusercontent.com/alejandroquinonesgamez/GEE_OSINT/main/Capturas/OSINT/hibp.png)

**Resultado:** 0 brechas conocidas en la base de datos de HIBP. No implica ausencia total de riesgo, pero indica que esa cuenta no figura en filtraciones públicas indexadas por el servicio.

### Resultados y análisis

Las técnicas OSINT pasivas **no sustituyen** al reconocimiento DNS, pero **refuerzan** el mapa del objetivo: confirman emails válidos, revelan organigrama, aportan documentos con metadatos sensibles y cruzan filiales (MANTELEC, IBERMAN, ASIME) con nombres de dominio. En un pentest, esta fase precedería o paralelizaría el escaneo de los subdominios descubiertos por `dnsenum`.

---

<a id="apartado-8"></a>

## 8. Resumen y conclusiones

### Resumen de inteligencia recopilada

| Categoría | Hallazgos principales |
|-----------|----------------------|
| **Dominios / TLD** | Conglomerado (MANTELEC, IBERMAN, ASIME, filiales internacionales); dominios activos y rutas bajo `grupo-gee.com` |
| **Subdominios** | >40 hosts; intranet, CRM, SSO, ADFS, oficina virtual, reservas, autodiscover |
| **NS** | GoDaddy (mayoría) y Puntum Consulting (iberdata.pt) |
| **MX** | Microsoft 365 centralizado; SPF hard fail en grupo-gee.com |
| **Vulnerabilidades DNS** | AXFR no explotable; cache snooping parcialmente exitoso |
| **Rangos IP** | Cyberneticos /24; **Vodafone ONO** 82.159.0.0/16 (servicios internos); 82.223.212.0/24; 195.23.128.0/24 |
| **OSINT / metadatos** | Emails (Hunter, theHarvester), PDFs públicos, servidor `greedatos`, perfiles LinkedIn |
| **Credenciales** | `talento@geelectromedico.com` sin brechas en HIBP |

### Técnicas pasivas y activas

Se ha recopilado información sobre la red y sistemas del objetivo mediante **técnicas pasivas** (fuentes abiertas, DNSDumpster, documentos públicos, Hunter.io) complementadas con técnicas activas DNS para validar subdominios y servidores.

| Técnica | Herramienta / método | Tipo | Deja rastro en el objetivo |
|---------|----------------------|------|----------------------------|
| DNSDumpster, Google Dorks | Web / buscador | Pasiva | No |
| theHarvester, Hunter.io, LinkedIn | OSINT | Pasiva | No |
| Análisis PDF + ExifTool | Metadatos | Pasiva | No |
| Have I Been Pwned | Consulta email | Pasiva | No |
| recon-ng (Hackertarget) | API / scraping | Pasiva | Mínimo |
| `dnsenum`, `dig`, `dnsrecon` | Consultas DNS directas | Activa | Sí |
| `nmap` dns-cache-snoop.nse | UDP/53 al NS | Activa | Sí |


### Conclusiones

El reconocimiento sobre **Grupo GEE** combina **DNS** (pasivo y activo) con **OSINT** (Google, LinkedIn, Hunter.io, PDFs y metadatos). Las técnicas DNS —DNSDumpster, `dnsenum`, `dig`, `nmap` NSE, recon-ng— cartografían hosts y servicios; las pasivas complementarias aportan personas, correos, documentos internos filtrados y nombres de infraestructura (`greedatos`) no siempre visibles en registros DNS.

En línea con el [apartado 8](#apartado-8) de este informe, GEE debe tratarse como **holding**: las interconexiones entre filiales (UTE, infraestructura compartida, oficina virtual en `greelocal.com`) amplían la superficie de ataque más allá del dominio raíz `grupo-gee.com`.

**Aspectos positivos de la postura del objetivo:**

- Transferencia de zona **deshabilitada** en todos los NS probados.
- Correo protegido por **Microsoft 365** con registro **SPF -all**.
- Separación parcial entre web pública (164.138.212.x) y servicios internos (82.159.201.x).

**Riesgos e inteligencia para fases posteriores:**

- Subdominios de **intranet**, **CRM**, **SFTP** y **ADFS** accesibles desde Internet.
- **Cache snooping** exitoso en ns13.domaincontrol.com y servidor Puntum, indicando resolución reciente de dominios del grupo.
- **Hosting compartido** (RevIP 413 en 164.138.212.77) con posible riesgo de vecindad.
- Servicios en **terceros** (Google, takeaspot.net, OVH) que amplían la superficie fuera del control directo del grupo.
- **Metadatos en PDFs** con rutas UNC y nombres de usuario; **39 emails** enumerados en Hunter.io para campañas dirigidas.
- Documentos de **seguridad de la información** (ENS, política SGI) expuestos o indexados, útiles para entender el marco de cumplimiento del grupo.

### Estrategia recomendada para las siguientes fases

1. **Escaneo de puertos** (`nmap`) sobre 82.159.201.0/24 y subdominios críticos detectados.
2. **Enumeración por certificados** (`ct-exposer` o crt.sh) para descubrir subdominios adicionales.
3. **Análisis web** de `intranet.*`, `crm.*`, `oficinavirtual.*` (tecnologías, autenticación, versiones).
4. **Verificación de correo** (registros DKIM/DMARC complementarios a SPF).
5. **Monitorización** de intentos de cache snooping y recursión DNS abierta en servidores propios.

---

*Informe autocontenido de la práctica «Reconocimiento DNS de una empresa» (véase [alcance y estructura](#alcance-y-estructura-del-informe)). Todas las capturas y documentos de apoyo (PDF) se encuentran en el repositorio [GEE_OSINT](https://github.com/alejandroquinonesgamez/GEE_OSINT), carpeta `Capturas/OSINT/`.*
