# 🛡️ Local SOC Log Analyzer & Attack Simulator

Herramienta ligera de análisis de registros (logs) y detección de intrusiones escrita en Python. Diseñada como laboratorio práctico de **Blue Team / Security Operations Center (SOC)** para identificar vectores de ataque comunes en servidores Linux y aplicaciones web.

## 🎯 Problema que resuelve
En entornos de monitoreo de seguridad, la revisión manual de archivos `auth.log` y `access.log` es ineficiente y propensa a errores. Este script automatiza el **Triage de Nivel 1 (Tier 1)** mediante reglas basadas en expresiones regulares (Regex) y correlación de eventos por umbral, transformando registros planos en alertas estructuradas en formato JSON listas para su ingesta en un SIEM o sistema de respuesta a incidentes.

## 🚀 Características Principales
- **Detección por Firmas (Web Attacks):** Identifica intentos de **SQL Injection (SQLi)** y **Path Traversal (LFI)** en registros de servidores HTTP (Apache/Nginx).
- **Correlación de Eventos (Fuerza Bruta):** Agrupa intentos fallidos de autenticación SSH por dirección IP e identifica ataques de diccionario o enumeración de usuarios.
- **Generador de Tráfico de Ataque (`--simulate`):** Incluye un módulo para generar logs sintéticos de ataques reales y validar las reglas de detección sin requerir infraestructura externa.
- **Exportación Estructurada:** Genera reportes legibles en CLI y exporta evidencias en formato `JSON` (Timestamp, Severidad, IP de origen, Payload y Línea de registro).
- **Cero Dependencias Externas:** Construido 100% con la librería estándar de Python 3 para máxima portabilidad.

## 📂 Estructura del Proyecto
```text
soc-log-analyzer/
├── soc_log_analyzer.py   # Motor principal de análisis y simulación
├── sample_security.log   # Archivo de logs de ejemplo (generado con --simulate)
├── soc_alerts.json       # Ejemplo de salida de alertas en formato JSON
├── .gitignore            # Archivos ignorados por control de versiones
└── README.md             # Documentación técnica del proyecto
```

## 🛠️ Uso Rápido

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/TU_USUARIO/soc-log-analyzer.git
   cd soc-log-analyzer
   ```

2. Ejecutar en modo de simulación (genera logs de prueba y los analiza):
   ```bash
   python soc_log_analyzer.py --simulate
   ```

3. Analizar un archivo de log personalizado:
   ```bash
   python soc_log_analyzer.py -f /var/log/auth.log -o alertas.json
   ```

## 🧠 Mapeo con MITRE ATT&CK
| Amenaza Detectada | Severidad | Táctica | Técnica MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **SSH Brute Force** | `MEDIUM` | Credential Access | **T1110** - Brute Force |
| **SQL Injection** | `HIGH` | Initial Access | **T1190** - Exploit Public-Facing Application |
| **Path Traversal** | `HIGH` | Collection / Discovery | **T1083** - File and Directory Discovery |

## 📄 Ejemplo de Alerta Generada (`soc_alerts.json`)
```json
[
    {
        "timestamp": "2026-10-23T18:20:00.000000",
        "severity": "HIGH",
        "type": "SQL Injection Attempt",
        "source_ip": "185.220.101.4",
        "evidence": "/login.php?user=admin'--",
        "line_number": 7
    }
]
```
