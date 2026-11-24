# 🛡️ Email Phishing Detector — Arquitectura Multicapa

Motor de detección de correos maliciosos diseñado bajo el principio de **Defensa en Profundidad (*Defense in Depth*)**. En lugar de depender de un único filtro estático, el sistema procesa cada correo a través de un pipeline secuencial de múltiples capas que desofuscan el contenido, validan la identidad del remitente y evalúan el riesgo de forma ponderada.

---

## 🔄 Flujo del Pipeline Multicapa

Un detector profesional divide el análisis en **8 etapas independientes** para maximizar la tasa de detección y minimizar los falsos positivos:

### 1. Ingesta y Parseo Estructural (MIME / RFC 5322)
* Recibe el correo en formato crudo (`.eml` o flujo SMTP) sin ejecutar ningún contenido.
* Separa las cabeceras (*headers*), el cuerpo en texto plano (`text/plain`), el cuerpo HTML (`text/html`) y aísla los archivos adjuntos o recursos embebidos.

### 2. Autenticación y Análisis de Cabeceras
* **Validación criptográfica:** Verifica los resultados de **SPF**, **DKIM** y **DMARC** para confirmar que el servidor emisor está autorizado por el dominio.
* **Consistencia de identidad:** Detecta discrepancias entre el remitente visible (`From`), la ruta de retorno (`Return-Path`) y la dirección de respuesta (`Reply-To`).
* **Trazado de saltos:** Analiza las cabeceras `Received` para identificar la IP de origen real y su reputación.

### 3. Normalización y Desofuscación *(Implementado)*
Neutraliza las técnicas de evasión que los atacantes usan para burlar expresiones regulares simples:
* **Decodificación multicapa:** Convierte contenido codificado en `Quoted-Printable`, `Base64` y entidades HTML (`&amp;`, `&#x2F;`).
* **Limpieza de caracteres invisibles:** Elimina espacios de ancho cero (*Zero-Width Spaces* como `\u200b`, `\u200c`) usados para fragmentar palabras clave.
* **Normalización Unicode (`NFKC`):** Convierte caracteres homóglifos o visualmente similares a su forma estándar.
* **Parseo HTML real:** Utiliza `BeautifulSoup4` para extraer atributos `href`, texto visible y detectar elementos ocultos mediante CSS (`display:none`, `visibility:hidden`, `opacity:0`).

### 4. Análisis de URLs e Inteligencia de Amenazas
* **Decodificación Punycode (`idna`):** Traduce dominios internacionalizados (`xn--...`) para exponer suplantaciones visuales.
* **Spoofing visual:** Compara el texto ancla del enlace contra la URL de destino real.
* **Heurística de enlaces:** Detecta URLs basadas en direcciones IP directas, acortadores (`bit.ly`, `tinyurl.com`) y TLDs de alto riesgo (`.xyz`, `.tk`, `.top`).
* **Enriquecimiento externo *(Roadmap)*:** Desacortado seguro de redirecciones, consulta de edad del dominio (WHOIS/RDAP) y reputación en APIs (VirusTotal, URLhaus, Google Safe Browsing).

### 5. Inspección de Adjuntos y Sandboxing *(Roadmap)*
* **Análisis estático:** Cálculo de hashes (SHA-256), validación de *magic bytes* (archivos renombrados) y detección de macros en documentos de Office.
* **Detección de Quishing:** Lectura de códigos QR incrustados en imágenes para extraer URLs ocultas.
* **Detonación aislada:** Ejecución controlada de adjuntos o enlaces sospechosos en un entorno *sandbox*.

### 6. Análisis Semántico y de Contenido (NLP / ML) *(Roadmap)*
* Detección de ingeniería social y ataques **BEC** (*Business Email Compromise*) que carecen de enlaces o adjuntos maliciosos.
* Clasificación de intención: urgencia artificial, suplantación de autoridad y solicitudes financieras anómalas.

### 7. Motor de Puntuación y Reglas (*Scoring Engine*) *(Implementado)*
Consolida las alertas de todas las capas en un puntaje de riesgo acumulativo:

| Indicador Detectado | Puntuación |
| :--- | :---: |
| URL basada en dirección IP directa | `+5` |
| Spoofing visual (texto ancla distinto al destino) | `+5` |
| Extensión de dominio de alto riesgo (TLD) | `+4` |
| Ofuscación mediante texto oculto por CSS | `+4` |
| Uso de acortador de URL | `+3` |
| Palabras clave de urgencia (por coincidencia única) | `+2` |

* **Umbral de veredicto:** Un puntaje igual o superior a **5 puntos** clasifica el correo como `PHISHING DETECTADO`.

### 8. Acción, Telemetría y Retroalimentación *(Roadmap)*
* **Acciones automáticas:** Entrega normal (riesgo bajo), inyección de banner de advertencia (riesgo medio) o cuarentena/bloqueo (riesgo alto).
* **Telemetría:** Registro estructurado en JSON para integración con SIEM y ajuste continuo de falsos positivos.

---

## 📁 Estructura del Proyecto

El código sigue una arquitectura modular con separación de responsabilidades:

```text
phishing_detector/
│
├── config.py       # Patrones RegEx y listas de IoCs (dominios, acortadores)
├── decoder.py      # Normalización Unicode, decodificación multicapa y parseo HTML
├── scanner.py      # Motor de evaluación y cálculo de puntuación de riesgo
└── main.py         # Punto de entrada y casos de prueba