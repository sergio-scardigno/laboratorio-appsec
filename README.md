# Laboratorio AppSec

Pega una web o un repo y obtén un análisis de seguridad con tres herramientas, con los hallazgos unificados y agrupados por categoría del [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction).

- **Semgrep y SonarQube** leen el código (SAST).
- **OWASP ZAP** prueba la web en marcha (DAST).
- **OWASP Juice Shop** es el objetivo de referencia, aislado en una red sin salida.

La idea que guía el informe: **distinguir "se miró y no hay nada" de "esta herramienta no puede verlo"**. Un análisis automático nunca demuestra que algo esté limpio.

## Cómo funciona

```
Web (127.0.0.1:8000) ─┐
                      ├─> lab/pipeline.py ─> findings.json + informe HTML + historial SQLite
CLI (lab scan) ───────┘        │
                               ├─ Obtener el código, sin ejecutar nada
                               ├─ Semgrep   (contenedor efímero, sin red)
                               ├─ SonarQube (scanner efímero -> servidor)
                               ├─ ZAP       (contenedor efímero)
                               └─ Normalizar -> mapear por CWE -> deduplicar -> informe

Servicios fijos: SonarQube + Postgres, Juice Shop (red interna, sin puertos publicados)
```

| Entrada | Semgrep y SonarQube | ZAP |
|---|---|---|
| Repo | Sí | No |
| Web | No | Sí, exige declarar autorización |
| Repo y web | Sí | Sí, exige declarar autorización |
| Preset Juice Shop | Sí | Sí, modo activo permitido |

### Mapeo al OWASP Top 10:2025

El CWE es el único dato común a las tres herramientas, así que el mapeo siempre sale de él. La tabla `data/owasp2025_cwe.json` se genera desde las páginas oficiales de OWASP con `make owasp-map`, que falla si el número de CWE no coincide con el que declara cada página.

- **Sin CWE reconocible:** va a "Sin mapear". Nunca se adivina.
- **Varios CWE:** el hallazgo cuenta en cada categoría que le corresponda, así que las filas suman más que el total.
- **Dos herramientas SAST coinciden** en archivo, CWE y línea (±3): cuenta como un hallazgo para ambas.
- **SAST y DAST con un CWE común:** se marca como correlación probable, sin fusionar. No hay un vínculo fiable entre una URL y una línea de código.
- **Reglas `former-hotspot` de Sonar:** salen como "por revisar", porque dependen del contexto.
- **Una herramienta falla:** el análisis queda como parcial y el informe lo dice arriba del todo.

En cada ejecución se comprueba que, por herramienta, crudos = normalizados + descartados con motivo.

## Puesta en marcha

Requisitos: Ubuntu 24.04, 4 vCPU, 8-12 GB de RAM y 50 GB de disco. Se recomienda una VM dedicada.

```bash
# Como root, una sola vez. Instala Docker y comprueba que arranca contenedores.
bash scripts/bootstrap-host.sh <usuario>

# Con ese usuario, en una sesión nueva.
make setup
```

`make setup` crea `.env` con secretos aleatorios, levanta los servicios, cambia la contraseña de admin de SonarQube, genera su token y descarga imágenes y reglas.

### En un contenedor LXC de Proxmox

Funciona en un LXC sin privilegios (probado con el kernel `7.0.2-6-pve` y Docker 29.9.3), con estas opciones en el host:

```bash
pct set <id> --features nesting=1,keyctl=1
pct resize <id> rootfs 50G
pct reboot <id>
pct exec <id> -- bash /ruta/a/appsec-lab/scripts/bootstrap-host.sh <usuario>
```

Una VM aísla mejor: en un LXC, este entorno comparte kernel con Proxmox mientras analiza código ajeno y ejecuta una aplicación vulnerable.

## Uso

### Web

```bash
make web
```

Muestra un enlace con el token de acceso. Solo escucha en `127.0.0.1`, así que desde otro equipo abre antes un túnel:

```bash
ssh -L 8000:127.0.0.1:8000 <usuario>@<host>
```

`deploy/appsec-lab-web.service` la deja como servicio de systemd.

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

### Repos privados de GitHub

1. Crea un [token fine-grained](https://github.com/settings/personal-access-tokens/new) con acceso solo a los repos que quieras analizar y un único permiso: **Contents: Read-only**. Ponle caducidad.
2. Añádelo a `.env`, que solo puede leer tu usuario:
   ```bash
   echo 'LAB_GITHUB_TOKEN=github_pat_...' >> .env
   ```
3. Reinicia `make web` si estaba en marcha. La CLI lo lee en cada análisis.

El token solo se envía a `github.com`, nunca a otros hosts. Va a git por variables de entorno, no en la URL ni en argumentos visibles con `ps`, y no queda en `request.json` ni en el historial. El código privado se envía solo a tu SonarQube local, pero el informe y `runs/<id>/` incluyen fragmentos de ese código.

Códigos de salida: `0` correcto, `1` superado `--fail-on`, `2` parcial o con error, `3` rechazado.

Cada análisis deja en `runs/<id>/` el informe `report.html`, los datos en `findings.json` y la salida cruda de cada herramienta.

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

**Comprobado en esta ejecución:**
- Por herramienta, crudos = normalizados, sin descartes: Semgrep 72, SonarQube 85 (igual que su propia API), ZAP 14.
- Una muestra aleatoria de 10 hallazgos de código, revisada a mano, corresponde al código citado. Es una comprobación de la muestra, no una tasa de falsos positivos.

**Lee estos números con cautela:**
- 80 hallazgos dependen del contexto; muchos son patrones como `Math.random()` que no siempre son un fallo. 168 no significa 168 vulnerabilidades.
- ZAP no es determinista: en tres análisis activos dio 12, 12 y 14 alertas, con alguna distinta. La inyección SQL apareció en los tres, con confianza baja según el propio ZAP.
- ZAP informó de peticiones sin respuesta (4 %, 11 % y 50 %). Es una cifra global: Juice Shop no se reinició y siguió respondiendo, y desde su red aislada no se llega a dominios externos, pero el dato no permite descartar otras causas.
- 43 archivos se analizaron de forma parcial en Semgrep, muchos de ellos fragmentos de ejercicio de `data/static/codefixes`.

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

El workflow `.github/workflows/juice-shop-scan.yml` ejecuta los tests y un análisis de Juice Shop, de forma manual y cada semana, y sube el informe como artifact. Falla solo si una herramienta falla: que Juice Shop tenga hallazgos es lo esperado.

## Licencias

Las reglas de Semgrep tienen su propia [licencia](https://semgrep.dev/legal/rules-license): no permite redistribuirlas ni ofrecerlas como servicio. Por eso se descargan en la instalación y no están en este repo.
