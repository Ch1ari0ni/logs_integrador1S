from datetime import datetime

def salvar_log(device, ip, so, servicos, caminho="scan_logs.txt"):
    with open(caminho, "a", encoding="utf-8") as f:
        f.write(f"Time: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')} \n")
        f.write(f"Device: {device}\n")
        f.write(f"IP: {ip}\n")
        f.write(f"SO: {so}\n")
        f.write("Open: \n")
        for s in servicos:
            f.write(f"  {s}\n")
        f.write("=" * 40 + "\n\n")
