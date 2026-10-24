#!/usr/bin/env python3
"""
Mini-SOC Log Analyzer & Attack Simulator
Descripción: Herramienta de análisis de logs para detección temprana de ataques
             de Fuerza Bruta, SQL Injection y Path Traversal.
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Umbral de intentos fallidos para considerar un ataque de Fuerza Bruta
BRUTE_FORCE_THRESHOLD = 3

# Patrones de Expresiones Regulares (Reglas de Detección del SOC)
PATTERNS = {
    "SSH_FAILED_LOGIN": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "SQL_INJECTION": re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?:GET|POST)\s+(?P<url>\S*(?:UNION(?:\s+|%20|\+)SELECT|OR(?:\s+|%20|\+)1=1|\'--|%27)\S*)',
        re.IGNORECASE
    ),
    "PATH_TRAVERSAL": re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?:GET|POST)\s+(?P<url>\S*(?:\.\./|\.\.%2f|/etc/passwd)\S*)',
        re.IGNORECASE
    ),
}


def generate_sample_logs(log_filepath: str) -> bool:
    """
    Genera un archivo de logs simulado con tráfico normal y vectores de ataque
    para probar el laboratorio SOC sin necesidad de infraestructura externa.
    """
    sample_logs = [
        "Oct 23 10:01:12 srv-web01 sshd[1024]: Accepted password for admin from 192.168.1.50 port 51234 ssh2",
        "Oct 23 10:02:01 srv-web01 sshd[1025]: Failed password for invalid user root from 45.33.32.156 port 44121 ssh2",
        "Oct 23 10:02:04 srv-web01 sshd[1026]: Failed password for invalid user root from 45.33.32.156 port 44122 ssh2",
        "Oct 23 10:02:07 srv-web01 sshd[1027]: Failed password for invalid user admin from 45.33.32.156 port 44123 ssh2",
        "Oct 23 10:02:10 srv-web01 sshd[1028]: Failed password for root from 45.33.32.156 port 44124 ssh2",
        '192.168.1.25 - - [23/Oct/2026:10:05:00 +0000] "GET /index.html HTTP/1.1" 200 1043',
        '185.220.101.4 - - [23/Oct/2026:10:06:15 +0000] "GET /login.php?user=admin\'-- HTTP/1.1" 200 512',
        '185.220.101.4 - - [23/Oct/2026:10:06:30 +0000] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 230',
        '103.14.26.99 - - [23/Oct/2026:10:08:11 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 189',
    ]

    try:
        with open(log_filepath, "w", encoding="utf-8") as file:
            for line in sample_logs:
                file.write(line + "\n")
        print(f"[+] Archivo de logs de prueba generado exitosamente en: {log_filepath}")
        return True
    except OSError as error:
        print(f"[!] Error al crear el archivo de simulación: {error}")
        return False


def analyze_logs(log_filepath: str) -> list:
    """
    Lee el archivo de logs línea por línea, aplica reglas de detección (Regex)
    y correlaciona eventos para generar una lista de alertas de seguridad.
    """
    alerts = []
    failed_ssh_counts = defaultdict(lambda: {"count": 0, "users": set()})

    try:
        path = Path(log_filepath)
        if not path.is_file():
            raise FileNotFoundError(f"No se encontró el archivo: {log_filepath}")

        with open(path, "r", encoding="utf-8", errors="replace") as file:
            for line_num, line in enumerate(file, start=1):
                # 1. Detección de intentos fallidos de SSH
                ssh_match = PATTERNS["SSH_FAILED_LOGIN"].search(line)
                if ssh_match:
                    ip = ssh_match.group("ip")
                    user = ssh_match.group("user")
                    failed_ssh_counts[ip]["count"] += 1
                    failed_ssh_counts[ip]["users"].add(user)
                    continue

                # 2. Detección de SQL Injection (SQLi)
                sqli_match = PATTERNS["SQL_INJECTION"].search(line)
                if sqli_match:
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "severity": "HIGH",
                        "type": "SQL Injection Attempt",
                        "source_ip": sqli_match.group("ip"),
                        "evidence": sqli_match.group("url"),
                        "line_number": line_num
                    })
                    continue

                # 3. Detección de Path Traversal / Directory Traversal
                lfi_match = PATTERNS["PATH_TRAVERSAL"].search(line)
                if lfi_match:
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "severity": "HIGH",
                        "type": "Path Traversal Attempt",
                        "source_ip": lfi_match.group("ip"),
                        "evidence": lfi_match.group("url"),
                        "line_number": line_num
                    })

        # Correlación de eventos: Evaluar si los fallos SSH superan el umbral de Fuerza Bruta
        for ip, data in failed_ssh_counts.items():
            if data["count"] >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "severity": "MEDIUM",
                    "type": "SSH Brute Force Detected",
                    "source_ip": ip,
                    "attempts": data["count"],
                    "targeted_users": sorted(list(data["users"]))
                })

    except FileNotFoundError as fnf_error:
        print(f"[!] Error de archivo: {fnf_error}")
    except PermissionError:
        print(f"[!] Error de permisos: No tienes acceso de lectura para '{log_filepath}'.")
    except Exception as error:
        print(f"[!] Error inesperado durante el análisis: {error}")

    return alerts


def export_report(alerts: list, output_filepath: str) -> None:
    """
    Muestra un resumen ejecutivo en consola y exporta las alertas en formato JSON
    listo para ser ingerido por un SIEM o sistema de tickets.
    """
    print("\n" + "=" * 60)
    print("       REPORTE DE INCIDENTES - LABORATORIO SOC LOCAL")
    print("=" * 60)

    if not alerts:
        print("[OK] Análisis completado. No se detectaron amenazas.")
        return

    for idx, alert in enumerate(alerts, start=1):
        print(f"\n[Alerta #{idx}] [{alert['severity']}] {alert['type']}")
        print(f"  |-- IP Origen : {alert['source_ip']}")
        if "evidence" in alert:
            print(f"  |-- Payload   : {alert['evidence']} (Línea {alert['line_number']})")
        if "attempts" in alert:
            print(f"  |-- Intentos  : {alert['attempts']} fallos")
            print(f"  +-- Usuarios  : {', '.join(alert['targeted_users'])}")

    try:
        with open(output_filepath, "w", encoding="utf-8") as json_file:
            json.dump(alerts, json_file, indent=4, ensure_ascii=False)
        print("\n" + "-" * 60)
        print(f"[+] Reporte JSON exportado correctamente en: {output_filepath}")
    except OSError as error:
        print(f"[!] No se pudo guardar el reporte JSON: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Mini-SIEM: Analizador de logs para detección de incidentes en un SOC Local."
    )
    parser.add_argument(
        "-f", "--file",
        default="sample_security.log",
        help="Ruta del archivo de log a analizar (por defecto: sample_security.log)"
    )
    parser.add_argument(
        "-o", "--output",
        default="soc_alerts.json",
        help="Ruta del archivo JSON de salida para las alertas"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Genera un archivo de logs con ataques simulados antes de analizar"
    )

    args = parser.parse_args()

    if args.simulate:
        generate_sample_logs(args.file)

    alerts = analyze_logs(args.file)
    export_report(alerts, args.output)


if __name__ == "__main__":
    main()
