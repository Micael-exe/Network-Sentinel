#!/usr/bin/env bash
# Instala as dependências de sistema no Kali Linux e valida o projeto.
set -euo pipefail

echo "[*] Instalando nmap, tshark, python3 e git..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y nmap tshark python3 git

echo "[*] Versões:"
nmap --version | head -n1
tshark --version | head -n1
python3 --version

echo "[*] Rodando testes..."
python3 -m unittest discover -s tests

echo
echo "[+] Tudo pronto. Próximos passos:"
echo "    python3 -m netsentinel demo                    # demonstração (sem root)"
echo "    sudo python3 -m netsentinel scan --learn       # 1ª varredura = baseline"
