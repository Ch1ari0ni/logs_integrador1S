#!/usr/bin/env python3
import subprocess, shutil, sys, os
from datetime import datetime
import re

# Importa a função de log do outro script (assumindo que está em 'logs.py')
from logs import salvar_log

def extrair_info_nmap(saida):
    linhas = saida.splitlines()
    ip = so = "desconhecido"
    servicos = []

    for linha in linhas:
        if linha.startswith("Nmap scan report for"):
            ip_match = re.search(r"\(([\d.]+)\)", linha)
            ip = ip_match.group(1) if ip_match else linha.split()[-1]
        elif linha.startswith("PORT") and "SERVICE" in linha:
            idx = linhas.index(linha) + 1
            while idx < len(linhas) and linhas[idx] and "open" in linhas[idx]:
                servicos.append(linhas[idx].strip())
                idx += 1
        elif "OS details:" in linha:
            so = linha.split(":", 1)[1].strip()
        elif "Running:" in linha and so == "desconhecido":
            so = linha.split(":", 1)[1].strip()

    return ip, so, servicos

def main():
    target = input("Alvo (IP ou domínio): ").strip()
    if not target:
        print("Nenhum alvo informado.")
        return

    nmap_exe = shutil.which("nmap") or r"C:\Program Files\Nmap\nmap.exe"
    if not os.path.exists(nmap_exe):
        print("Nmap não encontrado. Ajuste o caminho em nmap_exe.")
        sys.exit(1)

    cmd = [nmap_exe, "-sS", "-T4", "-O", target]
    try:
        resultado = subprocess.run(cmd, capture_output=True, text=True, check=True)
        ip, so, servicos = extrair_info_nmap(resultado.stdout)

        # Chamada do log 
        salvar_log(device=target, ip=ip, so=so, servicos=servicos)

        print("Scan completo. Log salvo.")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar Nmap: {e}")

if __name__ == "__main__":
    main()
