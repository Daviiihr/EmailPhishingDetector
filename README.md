# 🛡️ Email Phishing Detector — Arquitectura Multicapa

Motor de detección de correos maliciosos diseñado bajo el principio de **Defensa en Profundidad (*Defense in Depth*)**. En lugar de depender de un único filtro estático, el sistema procesa cada correo a través de un pipeline secuencial de **8 capas independientes** que parsean MIME de forma segura, validan la autenticación del remitente, desofuscan el contenido, analizan enlaces y adjuntos, evalúan ingeniería social/BEC y ejecutan acciones con telemetría SIEM.

---

## 🔄 Flujo del Pipeline Multicapa (8 Etapas Implementadas)

### 1. Ingesta y Parseo Estructural (MIME / RFC 5322) — `stages/ingestion.py`
* Recibe correos crudos (`.eml`, bytes RFC 5322 o texto/HTML directo) sin ejecutar contenido activo.
* Separa cabeceras multi-valor, cuerpo en texto plano (`text/plain`), cuerpo HTML (`text/html`) y aísla archivos adjuntos/recursos embebidos con límites seguros de tamaño.

### 2. Autenticación y Análisis de Cabeceras — `stages/headers.py`
* **Validación criptográfica:** Analiza `Authentication-Results`, `ARC-Authentication-Results` y `Received-SPF` para verificar **SPF**, **DKIM**, **DMARC** y **ARC**.
* **Consistencia de identidad:** Detecta discrepancias entre dominios organizacionales de `From`, `Return-Path` y `Reply-To`, además de **spoofing del nombre visible** (correo incrustado o suplantación de marcas protegidas).
* **Trazado de saltos (`Received`):** Reconstruye la cadena cronológica de servidores, identifica la IP pública de origen, detecta saltos anómalos y consulta listas de bloqueo de IPs.

### 3. Normalización y Desofuscación — `stages/normalization.py`
* **Decodificación multicapa:** Decodifica RFC 2047, repara *mojibake* (`ftfy`), procesa `Quoted-Printable`, `Base64` y entidades HTML (incluyendo doble codificación).
* **Caracteres invisibles y BiDi:** Elimina espacios de ancho cero (`\u200b`, `\u200c`, `\u200d`, `\ufeff`, `\u00ad`) y detecta controles bidireccionales críticos como RLO (`\u202e`).
* **Normalización Unicode (`NFKC`) y homóglifos:** Detecta y normaliza palabras que mezclan caracteres latinos con homóglifos cirílicos/griegos.
* **Parseo HTML real (`BeautifulSoup4`):** Extrae enlaces `href`, texto visible completo, texto oculto vía CSS (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, `hidden`), formularios `<form>` externos y redirecciones `<meta http-equiv="refresh">`.

### 4. Análisis de URLs e Inteligencia de Amenazas — `stages/url_analysis.py`, `enrichment/threat_intel.py`
* **Decodificación Punycode (`idna`) y homógrafos IDN:** Expone dominios `xn--...` y suplantaciones visuales.
* **Spoofing visual (`+5`):** Compara el dominio mostrado en el texto ancla contra el destino real.
* **Heurística de enlaces:** Detecta URLs por IP (IPv4/IPv6/ofuscadas), acortadores exactos (`bit.ly`, `tinyurl.com`, etc.), TLDs de alto riesgo (`.xyz`, `.tk`, `.top`, etc.), truco `@` en `netloc`, subdominios excesivos, esquemas peligrosos (`javascript:`, `data:`) y *typosquatting* de marcas (distancia de Levenshtein + *leetspeak*).
* **Enriquecimiento externo (opt-in vía `--enrich`):**
  * Desacortador seguro de redirecciones con protección **SSRF** (bloquea IPs privadas/loopback).
  * Consulta de antigüedad de dominio vía **RDAP** (`rdap.org`).
  * Adaptadores listos para **URLhaus**, **VirusTotal** (`VIRUSTOTAL_API_KEY`) y **Google Safe Browsing** (`GOOGLE_SAFE_BROWSING_API_KEY`).

### 5. Inspección de Adjuntos, Quishing y Sandboxing — `stages/attachments.py`
* **Análisis estático:** Cálculo de hashes (`SHA-256` / `MD5`) y cotejo contra listas de hashes maliciosos.
* **Validación de *magic bytes*:** Detecta archivos renombrados (p. ej., un ejecutable PE `MZ` disfrazado de `.pdf`), dobles extensiones (`factura.pdf.exe`), extensiones peligrosas y *HTML smuggling*.
* **Macros y archivos comprimidos:** Detecta macros VBA en documentos OOXML (`vbaProject.bin`) y OLE2 legados, además de inspeccionar archivos ZIP en memoria (ZIPs cifrados y ejecutables anidados).
* **Detección de Quishing (QR):** Interfaz `QrCodeDecoder` (compatible con `pyzbar` / OpenCV o decodificadores personalizados) que reenvía URLs extraídas de imágenes a la Etapa 4.
* **Detonación en Sandbox:** Interfaz `SandboxClient` con escáner estático local (EICAR y comandos PowerShell/WScript maliciosos) extensible a sandboxes externos.

### 6. Análisis Semántico y de Contenido (NLP / ML) — `stages/semantic.py`
* **Ingeniería social y BEC (*Business Email Compromise*):** Detecta ataques bilingües (ES/EN) sin enlaces ni adjuntos que combinan urgencia artificial, suplantación de autoridad/CEO, solicitudes financieras anómalas, solicitud de credenciales y presión de confidencialidad.
* **Clasificador ML explicable:** Modelo Naive Bayes multinomial (unigramas + bigramas) entrenado en corpus bilingüe phishing/BEC vs. legítimo, reportando probabilidad y características principales.

### 7. Motor de Puntuación y Reglas (*Scoring Engine*) — `scoring.py`, `pipeline.py`
Consolida y deduplica alertas de todas las capas en un puntaje ponderado y extrae IoCs estructurados:

| Indicador Principal | Puntuación |
| :--- | :---: |
| URL basada en dirección IP directa | `+5` |
| Spoofing visual (texto ancla distinto al destino) | `+5` |
| Fallo DMARC / Display-name spoofing / BEC / Punycode / Typosquatting | `+5` |
| Extensión de dominio de alto riesgo (TLD) | `+4` |
| Ofuscación mediante texto oculto por CSS / Fallo SPF o DKIM | `+4` |
| Uso de acortador de URL | `+3` |
| Palabras clave de urgencia (por coincidencia única) | `+2` |
| Adjuntos maliciosos (macros, magic mismatch, doble extensión, sandbox) | `+6` a `+10` |

* **Umbrales de veredicto y acción:**
  * `0–2` puntos: `LOW` → `CLEAN` → `ALLOW`
  * `3–4` puntos: `MEDIUM` → `SUSPICIOUS` → `WARN`
  * `5–11` puntos: `HIGH` → `PHISHING_DETECTED` → `QUARANTINE`
  * `>= 12` puntos: `CRITICAL` → `PHISHING_DETECTED` → `BLOCK`

### 8. Acción, Telemetría y Retroalimentación — `stages/actions.py`, `telemetry.py`, `feedback.py`
* **Acciones automáticas:** Entrega normal (`ALLOW`), inyección segura de banner de advertencia HTML (`WARN`), o aislamiento en cuarentena (`.eml` + `.report.json`) para `QUARANTINE`/`BLOCK`.
* **Telemetría SIEM:** Registro estructurado en formato JSONL compatible con pipelines SIEM/ECS.
* **Bucle de retroalimentación:** Persistencia de feedback de analistas (`false_positive`, `false_negative`, `confirmed_phishing`) que ajusta dinámicamente `allowlist`/`blocklist`.

---

## 📁 Estructura del Proyecto

```text
EmailPhishingDetector/
├── main.py                              # Punto de entrada CLI / demo
├── pyproject.toml                       # Metadatos y configuración de paquete/pytest
├── requirements.txt                     # Dependencias Python
├── phishing_detector/
│   ├── __init__.py                      # API pública del paquete
│   ├── __main__.py                      # Soporte `python -m phishing_detector`
│   ├── config.py                        # IoCs, pesos, umbrales y configuración
│   ├── models.py                        # Modelos de dominio y contexto del pipeline
│   ├── scoring.py                       # Etapa 7: Motor de puntuación y extractor IoC
│   ├── pipeline.py                      # Orquestador multicapa (`PhishingPipeline`)
│   ├── telemetry.py                     # Etapa 8: Logger SIEM JSONL
│   ├── feedback.py                      # Etapa 8: Store de feedback y allow/blocklist
│   ├── cli.py                           # Interfaz de línea de comandos
│   ├── enrichment/
│   │   └── threat_intel.py              # Unshortener SSRF-safe, RDAP, URLhaus/VT/GSB
│   └── stages/
│       ├── base.py                      # Clase base `PipelineStage` con métricas
│       ├── ingestion.py                 # Etapa 1: Parseo MIME / RFC 5322
│       ├── headers.py                   # Etapa 2: SPF/DKIM/DMARC y saltos Received
│       ├── normalization.py             # Etapa 3: Decodificación, NFKC, homóglifos, HTML
│       ├── url_analysis.py              # Etapa 4: Heurística URL, Punycode y spoofing
│       ├── attachments.py               # Etapa 5: Hashes, magic bytes, macros, ZIP, QR
│       ├── semantic.py                  # Etapa 6: BEC, ingeniería social y ML Naive Bayes
│       └── actions.py                   # Etapa 8: ALLOW, banner WARN y cuarentena
├── samples/                             # Correos `.eml` de ejemplo (limpio, phishing, BEC, malware)
└── tests/                               # Suite completa de pruebas unitarias e integración
```

---

## 🚀 Instalación y Uso

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Ejecutar demostración sobre los correos de ejemplo
```bash
python main.py demo
# o directamente:
python -m phishing_detector demo
```

### Escanear un archivo `.eml` o un directorio completo
```bash
python -m phishing_detector scan samples/02_obfuscated_phishing.eml
python -m phishing_detector scan samples/02_obfuscated_phishing.eml --json --quarantine-dir ./quarantine --telemetry-log ./telemetry.jsonl
python -m phishing_detector scan-dir samples/
```

### Habilitar enriquecimiento externo (RDAP / URLhaus / VirusTotal / Safe Browsing)
```bash
export VIRUSTOTAL_API_KEY="tu_api_key"
export GOOGLE_SAFE_BROWSING_API_KEY="tu_api_key"
python -m phishing_detector scan samples/02_obfuscated_phishing.eml --enrich
```

### Registrar retroalimentación de analista
```bash
python -m phishing_detector feedback <trace_id> --label false_positive --domain empresa-confiable.cl --store feedback.jsonl
python -m phishing_detector scan correo.eml --feedback-store feedback.jsonl
```

### Uso desde Python
```python
from phishing_detector import DetectorConfig, PhishingPipeline

config = DetectorConfig(
    quarantine_dir="./quarantine",
    telemetry_log_path="./telemetry.jsonl",
)
pipeline = PhishingPipeline(config=config)
report = pipeline.analyze_file("samples/02_obfuscated_phishing.eml")

print(report.verdict, report.risk_score, report.recommended_action)
```

### Ejecutar pruebas
```bash
pytest -v
```
