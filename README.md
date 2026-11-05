# Laboratorio AppSec

[![Análisis de Juice Shop](https://github.com/sergio-scardigno/laboratorio-appsec/actions/workflows/juice-shop-scan.yml/badge.svg)](https://github.com/sergio-scardigno/laboratorio-appsec/actions/workflows/juice-shop-scan.yml)
[![Licencia MIT](https://img.shields.io/badge/licencia-MIT-blue)](LICENSE)

Pega una web o un repo y obtén un único informe de seguridad: **Semgrep y SonarQube** leen el código, **OWASP ZAP** prueba la web en marcha, y los hallazgos se agrupan por categoría del [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction).

![Matriz del informe: hallazgos por categoría del OWASP Top 10:2025 y por herramienta](docs/img/informe-matriz.png)

La idea que guía el informe es **distinguir "se miró y no hay nada" de "esta herramienta no puede verlo"**. Un análisis automático nunca demuestra que algo esté limpio.

> **In English:** a self-hosted lab that runs Semgrep, SonarQube and OWASP ZAP against a repo or a website, normalizes the findings by CWE and maps them to the OWASP Top 10:2025 in one HTML report. OWASP Juice Shop is the reference target, isolated on a network with no way out. The documentation is in Spanish.

## Qué aporta

- **Un solo informe** para tres herramientas que no comparten formato, gravedad ni categorías.
- **Sin adivinar:** el mapeo sale del CWE y de la tabla oficial de OWASP. Lo que no encaja queda en "Sin mapear".
- **Sin falsa calma:** un cero, una herramienta que no se ejecutó y una que falló se ven distintos.
- **Autorización explícita** antes de enviar una sola petición a una web.
- **Pensado para código no confiable:** los repos analizados nunca se ejecutan y no pueden ocultarse sus propios hallazgos.

## Inicio rápido

Necesitas Ubuntu 24.04 con 4 vCPU, 8-12 GB de RAM y 50 GB de disco, preferiblemente en una VM dedicada.

```bash
git clone https://github.com/sergio-scardigno/laboratorio-appsec.git
cd laboratorio-appsec

# Como root, una sola vez: instala Docker y comprueba que arranca contenedores
sudo bash scripts/bootstrap-host.sh "$USER"
```

Abre una sesión nueva para que tu usuario pueda usar Docker y, desde la carpeta del proyecto:

```bash
make setup
make web
```

`make setup` crea `.env` con secretos aleatorios, levanta los servicios, cambia la contraseña de admin de SonarQube, genera su token y descarga imágenes y reglas. `make web` muestra un enlace con el token de acceso.

La web solo escucha en `127.0.0.1`. Desde otro equipo, abre antes un túnel:

```bash
ssh -L 8000:127.0.0.1:8000 <usuario>@<host>
```

Pulsa **Analizar Juice Shop** para ver un informe completo en unos 10 minutos.

![Formulario de la web: Juice Shop como prueba rápida, o un repo y una web propios](docs/img/web-formulario.png)

## Cómo funciona

```mermaid
flowchart LR
    A[Web local o CLI] --> P[Pipeline]
    P --> C[Código, sin ejecutar nada]
    C --> SG[Semgrep]
    C --> SQ[SonarQube]
    P --> Z[ZAP]
    Z -.analiza.-> W[Web objetivo o<br/>Juice Shop aislado]
    SG --> N[Normalizar, mapear por CWE<br/>y deduplicar]
    SQ --> N
    Z --> N
    N --> R[Informe HTML, findings.json<br/>e historial]
```

Los escáneres son contenedores efímeros que corren en serie, con límites de memoria y tiempo. SonarQube, su base de datos y Juice Shop son servicios fijos.

| Entrada | Semgrep y SonarQube | ZAP |
|---|---|---|
| Repo | Sí | No |
| Web | No | Sí, exige declarar autorización |
| Repo y web | Sí | Sí, exige declarar autorización |
| Preset Juice Shop | Sí | Sí, modo activo permitido |

### Mapeo al OWASP Top 10:2025

El CWE es el único dato común a las tres herramientas, así que el mapeo siempre sale de él. La tabla `data/owasp2025_cwe.json` se genera desde las páginas oficiales de OWASP con `make owasp-map`, que falla si el número de CWE no coincide con el que declara cada página.

- **Sin CWE reconocible:** va a "Sin mapear".
- **Varios CWE:** el hallazgo cuenta en cada categoría que le corresponda, así que las filas suman más que el total.
- **Dos herramientas SAST coinciden** en archivo, CWE y línea (±3): cuenta como un hallazgo para ambas.
- **SAST y DAST con un CWE común:** se marca como correlación probable, sin fusionar. No hay un vínculo fiable entre una URL y una línea de código.
- **Reglas `former-hotspot` de Sonar:** salen como "por revisar", porque dependen del contexto.
- **Una herramienta falla:** el análisis queda como parcial y el informe lo dice arriba del todo.

En cada ejecución se comprueba que, por herramienta, crudos = normalizados + descartados con motivo.

## Resultados sobre Juice Shop

Ejecución real con Juice Shop v20.3.0 y ZAP en modo activo: **168 hallazgos, 80 por revisar a mano**, en 10,7 minutos (4 vCPU, 12 GB de RAM).

| Categoría | Semgrep | SonarQube | ZAP | Total |
|---|---:|---:|---:|---:|
| A01 Broken Access Control | 10 | 35 | 5 | 50 |
| A02 Security Misconfiguration | 0 | 1 | 0 | 1 |
| A03 Software Supply Chain Failures | 7 | 0 | 0 | 7 |
| A04 Cryptographic Failures | 13 | 58 | 0 | 71 |
| A05 Injection | 22 | 14 | 1 | 35 |
| A06 Insecure Design | 5 | 0 | 5 | 10 |
| A07 Authentication Failures | 4 | 4 | 0 | 7 |
| A08 Software or Data Integrity Failures | 10 | 1 | 0 | 11 |
| A09 Security Logging & Alerting Failures | 0 | 5 | 0 | 5 |
| A10 Mishandling of Exceptional Conditions | 0 | 1 | 1 | 2 |
| Sin mapear | 8 | 1 | 2 | 11 |

Un hallazgo cuenta en cada categoría de sus CWE y para cada herramienta que lo detecta, por eso las columnas y las filas suman más que 168.

**El mismo fallo desde dos ángulos.** La inyección SQL del login aparece en el código (Semgrep, `routes/login.ts:34`) y en la web (ZAP, `POST /rest/user/login`), y queda marcada como correlación probable. SonarQube Community no la detecta.

![Detalle de la inyección SQL que encuentra ZAP en el login y en la búsqueda de productos](docs/img/informe-hallazgo.png)

**Comprobado en esta ejecución:**

- Por herramienta, crudos = normalizados, sin descartes: Semgrep 72, SonarQube 85 (igual que su propia API), ZAP 14.
- Una muestra aleatoria de 10 hallazgos de código, tomada en un análisis anterior con las mismas herramientas, corresponde al código citado. Es una comprobación de esa muestra, no una tasa de falsos positivos.

**Lee estos números con cautela:**

- 80 hallazgos dependen del contexto; muchos son patrones como `Math.random()` que no siempre son un fallo. 168 no significa 168 vulnerabilidades.
- ZAP no es determinista: en tres análisis activos dio 12, 12 y 14 alertas, con alguna distinta. La inyección SQL apareció en los tres, con confianza baja según el propio ZAP.
- ZAP informó de peticiones sin respuesta (4 %, 11 % y 50 %). Es una cifra global: Juice Shop no se reinició y siguió respondiendo, y desde su red aislada no se llega a dominios externos, pero el dato no permite descartar otras causas.
- 43 archivos se analizaron de forma parcial en Semgrep, muchos de ellos fragmentos de ejercicio de `data/static/codefixes`.

## Uso

### CLI

```bash
# Juice Shop: código + web, con ataque real
.venv/bin/lab scan --preset juice-shop --active

# Un repo público
.venv/bin/lab scan --repo https://github.com/OWASP/NodeGoat

# Una web tuya, en modo pasivo
.venv/bin/lab scan --url https://mi-web.example --i-am-authorized

# Una web tuya, atacándola
.venv/bin/lab scan --url https://mi-web.example --i-am-authorized --active --confirm-active

# Como puerta de calidad en una app real
.venv/bin/lab scan --repo https://github.com/org/app --fail-on high

# Historial
.venv/bin/lab runs
```

Códigos de salida: `0` correcto, `1` superado `--fail-on`, `2` parcial o con error, `3` rechazado.

Cada análisis deja en `runs/<id>/` el informe `report.html`, los datos en `findings.json` y la salida cruda de cada herramienta.

### Repos privados de GitHub

1. Crea un [token fine-grained](https://github.com/settings/personal-access-tokens/new) con acceso solo a los repos que quieras analizar y un único permiso: **Contents: Read-only**. Ponle caducidad.
2. Añádelo a `.env`, que solo puede leer tu usuario:
   ```bash
   echo 'LAB_GITHUB_TOKEN=github_pat_...' >> .env
   ```
3. Reinicia `make web` si estaba en marcha. La CLI lo lee en cada análisis.

El token solo se envía a `github.com`, nunca a otros hosts. Va a git por variables de entorno, no en la URL ni en argumentos visibles con `ps`, y no queda en `request.json` ni en el historial. El código privado se envía solo a tu SonarQube local, pero el informe y `runs/<id>/` incluyen fragmentos de ese código: trátalos como privados.

### Como servicio

`deploy/appsec-lab-web.service` deja la web como servicio de systemd. Sustituye antes el usuario y la ruta.

### En un contenedor LXC de Proxmox

Funciona en un LXC sin privilegios (probado con el kernel `7.0.2-6-pve` y Docker 29.9.3), con estas opciones en el host:

```bash
pct set <id> --features nesting=1,keyctl=1
pct resize <id> rootfs 50G
pct reboot <id>
pct exec <id> -- bash /ruta/a/appsec-lab/scripts/bootstrap-host.sh <usuario>
```

Una VM aísla mejor: en un LXC, este entorno comparte kernel con Proxmox mientras analiza código ajeno y ejecuta una aplicación vulnerable.

## Solo analiza lo que tengas permiso de analizar

ZAP envía peticiones reales incluso en modo pasivo, y en modo activo ataca: puede alterar datos o tumbar la web. Analizar sitios ajenos sin permiso puede ser ilegal.

Por eso cualquier web distinta del preset exige declarar autorización, el modo activo exige una segunda confirmación, y ambas quedan registradas. El laboratorio no puede comprobar que esas declaraciones sean ciertas: la responsabilidad es de quien lo usa.

## Seguridad del propio laboratorio

**Repos no confiables**

- Clonado superficial, sin hooks ni submódulos, y solo por `https://`. Nunca se compila ni se ejecuta nada.
- Se borran `.semgrepignore` y `sonar-project.properties`, y Semgrep corre con `--disable-nosem` y `--no-git-ignore`, para que un repo no pueda ocultarse sus propios hallazgos. Los comentarios `NOSONAR` sí pueden silenciar a SonarQube.
- Escáneres con el código en solo lectura, `--cap-drop ALL`, `no-new-privileges` y límites de memoria y procesos. Semgrep corre sin red.

**Exposición**

- Web y SonarQube solo en `127.0.0.1`.
- La web exige token, valida `Host` y `Origin` frente a DNS rebinding y CSRF, y usa una cookie `HttpOnly` y `SameSite=Strict`.
- Juice Shop va en una red `internal`, sin salida a internet ni a la LAN.
- El informe escapa todo el contenido analizado, lleva una CSP con nonce y no copia el código de los posibles secretos.

**Riesgo aceptado:** quien pertenece al grupo `docker` equivale a root en el host. Por eso el host debe dedicarse a esto.

## Límites

- **Dependencias (A03):** ninguna de las tres las analiza, así que A03 queda casi vacía aunque Juice Shop use dependencias vulnerables. El siguiente paso natural es añadir un SCA como Trivy u osv-scanner.
- **Diseño y registros (A06 y A09):** apenas se detectan con escáneres.
- **SonarQube Community:** no hace análisis de flujo; no detecta la inyección SQL de `routes/login.ts`.
- **Falsos negativos:** en un repo de prueba, ninguna herramienta detectó una contraseña escrita en una constante (`const password = "..."`).
- **ZAP sin autenticación:** no llega a lo que está detrás del login.
- **Limpieza:** cada análisis deja un proyecto en SonarQube y su carpeta en `runs/`; no se borran solos.

## Desarrollo

```bash
make test       # Tests con salidas reales recortadas (tests/fixtures)
make owasp-map  # Regenera la tabla CWE -> OWASP
```

El workflow `.github/workflows/juice-shop-scan.yml` ejecuta los tests y un análisis de Juice Shop al subir código a `main`, cada semana y de forma manual, y sube el informe como artifact. Falla solo si una herramienta falla: que Juice Shop tenga hallazgos es lo esperado.

## Cómo se construyó

Este laboratorio se construyó con ayuda de [Claude Code](https://claude.com/claude-code), que aparece como coautor en el historial de commits.

## Licencia

El código de este repo se publica bajo [licencia MIT](LICENSE).

Las reglas de Semgrep tienen su propia [licencia](https://semgrep.dev/legal/rules-license), que no permite redistribuirlas ni ofrecerlas como servicio. Por eso se descargan en la instalación y no están en este repo.
