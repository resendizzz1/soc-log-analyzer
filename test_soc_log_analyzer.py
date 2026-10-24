#!/usr/bin/env python3
"""
Suite de Pruebas Unitarias para el Analizador de Logs del SOC Local.
Valida Verdaderos Positivos (detección de ataques) y Falsos Positivos (tráfico legítimo).
"""

import unittest
import tempfile
import os
from soc_log_analyzer import analyze_logs


class TestSOCLogAnalyzer(unittest.TestCase):
    """Pruebas automatizadas para las reglas de detección y correlación del SOC."""

    def setUp(self):
        """Crea un archivo temporal antes de cada prueba."""
        self.temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8")

    def tearDown(self):
        """Elimina el archivo temporal después de cada prueba."""
        self.temp_file.close()
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def _write_logs_and_analyze(self, log_lines: list) -> list:
        """Escribe líneas en el archivo temporal y ejecuta el motor de análisis."""
        for line in log_lines:
            self.temp_file.write(line + "\n")
        self.temp_file.flush()
        self.temp_file.close()
        return analyze_logs(self.temp_file.name)

    def test_legitimate_traffic_no_false_positives(self):
        """Verifica que el tráfico normal NO genere alertas (0 Falsos Positivos)."""
        normal_logs = [
            "Oct 23 10:01:12 srv-web01 sshd[1024]: Accepted password for admin from 192.168.1.50 port 51234 ssh2",
            '192.168.1.25 - - [23/Oct/2026:10:05:00 +0000] "GET /index.html HTTP/1.1" 200 1043',
            '192.168.1.25 - - [23/Oct/2026:10:05:10 +0000] "POST /api/login HTTP/1.1" 200 512',
            # Solo 2 fallos de SSH (por debajo del umbral de 3) no deben disparar Fuerza Bruta
            "Oct 23 10:02:01 srv-web01 sshd[1025]: Failed password for admin from 10.0.0.5 port 44121 ssh2",
            "Oct 23 10:02:04 srv-web01 sshd[1026]: Failed password for admin from 10.0.0.5 port 44122 ssh2",
        ]
        alerts = self._write_logs_and_analyze(normal_logs)
        self.assertEqual(len(alerts), 0, "El tráfico legítimo no debería disparar alertas.")

    def test_ssh_brute_force_detection(self):
        """Verifica que 3 o más intentos fallidos desde una misma IP disparen alerta de Fuerza Bruta."""
        brute_force_logs = [
            "Oct 23 10:02:01 srv-web01 sshd[1025]: Failed password for invalid user root from 45.33.32.156 port 44121 ssh2",
            "Oct 23 10:02:04 srv-web01 sshd[1026]: Failed password for invalid user admin from 45.33.32.156 port 44122 ssh2",
            "Oct 23 10:02:07 srv-web01 sshd[1027]: Failed password for root from 45.33.32.156 port 44123 ssh2",
        ]
        alerts = self._write_logs_and_analyze(brute_force_logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "SSH Brute Force Detected")
        self.assertEqual(alerts[0]["source_ip"], "45.33.32.156")
        self.assertEqual(alerts[0]["attempts"], 3)
        self.assertEqual(alerts[0]["targeted_users"], ["admin", "root"])

    def test_sql_injection_detection(self):
        """Verifica la detección de payloads de SQL Injection (clásicos y codificados en URL)."""
        sqli_logs = [
            '185.220.101.4 - - [23/Oct/2026:10:06:15 +0000] "GET /login.php?user=admin\'-- HTTP/1.1" 200 512',
            '185.220.101.4 - - [23/Oct/2026:10:06:30 +0000] "GET /item.php?id=1%20UNION%20SELECT%201,2 HTTP/1.1" 500 230',
        ]
        alerts = self._write_logs_and_analyze(sqli_logs)
        self.assertEqual(len(alerts), 2)
        for alert in alerts:
            self.assertEqual(alert["type"], "SQL Injection Attempt")
            self.assertEqual(alert["severity"], "HIGH")

    def test_path_traversal_detection(self):
        """Verifica la detección de ataques de salto de directorio (Path Traversal / LFI)."""
        lfi_logs = [
            '103.14.26.99 - - [23/Oct/2026:10:08:11 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 189',
        ]
        alerts = self._write_logs_and_analyze(lfi_logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "Path Traversal Attempt")
        self.assertEqual(alerts[0]["source_ip"], "103.14.26.99")


if __name__ == "__main__":
    unittest.main(verbosity=2)
