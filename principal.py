import nmap
from logs import salvar_txt
from datetime import datetime

scanner = nmap.PortScanner(nmap_search_path=("C:\\Program Files (x86)\\Nmap\\nmap.exe",)) #localizar nmap

# -sS = scan steath
# -sV = sevice version
# -O = operational system
# -Pn = deactivate host discovery
# --osscan-guess = supor OS
# --version-light = fast service detection
# --max-retries = self-explain
# --host-timeout = self-explain

def varredura_ot(ip):
    print(f"Varredura OT iniciada em {ip}")
    scanner.scan(ip, arguments='-sS -sV --version-light -O --osscan-guess -Pn --max-retries 2 --host-timeout 30s') #
    return scanner.all_hosts()

def varredura_iot(ip):
    print(f"Varredura IoT iniciada em {ip}")
    scanner.scan(ip, arguments='-sS -sV -O --osscan-guess -Pn')
    return scanner.all_hosts()

def varredura_ti(ip):
    print(f"Varredura TI iniciada em {ip}")
    scanner.scan(ip, arguments='-Pn -sS -sV -O --osscan-guess')
    return scanner.all_hosts()

def varredura_completa(ip, tipo):
    try:
        if tipo == "OT":
            hosts = varredura_ot(ip)
        elif tipo == "IoT":
            hosts = varredura_iot(ip)
        elif tipo == "TI":
            hosts = varredura_ti(ip)
        else:
            print("Tipo de dispositivo desconhecido. Realizando varredura genérica.")
            scanner.scan(ip, arguments='-Pn -p 1-1024 -sV')
            hosts = scanner.all_hosts()
        return hosts
    except Exception as e:
        return f"Erro na varredura: {e}"

if __name__ == "__main__":
    ip = input("IP ou rede (ex: 192.168.0.0/24): ")
    tipo = input("Tipo de dispositivo (OT, IoT, TI): ")

    try:
        resultado = varredura_completa(ip, tipo)

        print("\n    Resultado da Varredura    ")
        if isinstance(resultado, list):
            for host in resultado:
                print(f"\nHost: {host}")
                servicos = []
                so = "não identificado"

                if 'tcp' in scanner[host]:
                    for porta in scanner[host]['tcp']:
                        info = scanner[host]['tcp'][porta]
                        nome_servico = f"{info['name']} {info.get('product', '')} {info.get('version', '')}".strip()
                        servicos.append(f"{porta}/tcp -> {nome_servico}")
                        print(f"Porta {porta}/tcp -> {nome_servico}")

                if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                    so = scanner[host]['osmatch'][0]['name']
                    print(f"Sistema Operacional: {so} (Acurácia: {scanner[host]['osmatch'][0]['accuracy']}%)")
                else:
                    print("Sistema Operacional: não identificado")

                # Salvar log
                salvar_txt(device=tipo, ip=host, so=so, servicos=servicos)

            print("\nScan completo. Log TXT salvo.")
        else:
            print(resultado)
    except Exception as e:
        print(f"Erro ao executar varredura: {e}")
