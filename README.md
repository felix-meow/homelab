# Homelab – Cybersecurity Portfolio

Un homelab complet de securitate cibernetica, construit pentru a demonstra abilitati practice in domeniul cybersecurity. Include 10 tool-uri proprii, de la scanning retea la detectare keylogger, toate dezvoltate in Python.

## Despre Proiect

Acest homelab reprezinta fundatia portofoliului meu de securitate cibernetica. Fiecare tool este construit de la zero, cu scopul de a intelege in profunzime conceptele din spatele securitatii ofensive si defensive.

Obiective:
git push -u origin master- Demonstrarea abilitatilor practice in cybersecurity
- Intelegerea profunda a protocoalelor si vulnerabilitatilor
- Crearea unui portofoliu solid pentru cariera in securitate
- Automatizarea si integrarea in homelab

## Arhitectura Homelab

Componente:

  Laptop (Windows 11)     - Host principal
  WSL 2 (Ubuntu)          - Mediu de dezvoltare
  Docker                  - Containerizare (n8n, Ollama, PostgreSQL)
  NetHunter (Redmi Note 8 Pro) - Securitate mobila
  Python 3.14             - Limbaj principal pentru tool-uri

## Structura Proiectelor

homelab/
├── README.md                          # Acest fisier
├── venv/                              # Mediu virtual Python
├── projects/
│   ├── port-scanner/                  # 1. Port Scanner
│   ├── packet-sniffer/                # 2. Packet Sniffer
│   ├── file-integrity-monitor/        # 3. File Integrity Monitor
│   ├── web-vuln-scanner/              # 4. Web Vulnerability Scanner
│   ├── ids/                           # 5. Intrusion Detection System
│   ├── password-cracker/              # 6. Password Cracker
│   ├── phishing-detector/             # 7. Phishing Detector
│   ├── firewall-simulator/            # 8. Firewall Simulator
│   ├── encrypted-chat/                # 9. Encrypted Chat
│   └── keylogger-detector/            # 10. Keylogger Detector
└── assets/
    └── diagram.png                    # Diagrama homelab

## Proiecte

### 1. Port Scanner
Scanner TCP simplu pentru identificarea serviciilor deschise.

python3 port_scanner.py -H target.com -p 1-1000

### 2. Packet Sniffer
Captura si analiza pachete de retea cu filtrare BPF.

sudo python3 sniffer.py -i eth0 -f "tcp port 80" -c 10

### 3. File Integrity Monitor (FIM)
Monitorizeaza integritatea fisierelor folosind hash-uri SHA256.

python3 fim.py -d /path/to/monitor --init

### 4. Web Vulnerability Scanner
Scanner automat pentru XSS, SQLi, LFI si Open Redirect.

python3 scanner.py -u http://target.com -d 2

### 5. Intrusion Detection System (IDS)
Detecteaza port scan-uri, SYN flood, ICMP flood si brute force.

sudo python3 ids_file.py -i eth0 -t 30

### 6. Password Cracker
Suporta atacuri cu dictionar, brute-force si hibride.

python3 cracker.py -t <hash> -a md5 -m dictionary

### 7. Phishing Detector
Analizeaza email-uri pentru detectarea tentativelor de phishing.

python3 detector.py -s "Subject" -b "Body"

### 8. Firewall Simulator
Simuleaza reguli de firewall cu filtrare IP/port/protocol.

python3 firewall.py -s 20

### 9. Encrypted Chat
Chat securizat cu criptare AES (Fernet) si autentificare.

Server:
python3 server.py -p 5000 --password chat123

Client:
python3 client.py -s 127.0.0.1 -p 5000 -u Alice --password chat123

### 10. Keylogger Detector
Detecteaza keylogger-i prin analiza proceselor si fisierelor.

python3 detector.py

## Instalare

1. Cloneaza repository-ul:
git clone https://github.com/felix-meow/homelab.git
cd homelab

2. Creeaza mediul virtual:
python3 -m venv venv
source venv/bin/activate

3. Instaleaza dependintele pentru fiecare proiect:

Port Scanner:
cd projects/port-scanner
pip install -r requirements.txt

Packet Sniffer (necesita libpcap):
sudo apt install libpcap-dev -y
cd projects/packet-sniffer
pip install -r requirements.txt

File Integrity Monitor:
cd projects/file-integrity-monitor
pip install -r requirements.txt

Web Vulnerability Scanner:
cd projects/web-vuln-scanner
pip install -r requirements.txt

IDS:
cd projects/ids
pip install -r requirements.txt

Password Cracker:
cd projects/password-cracker
pip install -r requirements.txt

Phishing Detector:
cd projects/phishing-detector
pip install -r requirements.txt

Firewall Simulator:
cd projects/firewall-simulator
pip install -r requirements.txt

Encrypted Chat:
cd projects/encrypted-chat
pip install -r requirements.txt

Keylogger Detector:
cd projects/keylogger-detector
pip install -r requirements.txt

## Tehnologii Utilizate

  Limbaj        Python 3.14+
  Retea         Scapy, socket, requests
  Securitate    cryptography, hashlib
  Sistem        psutil, os, subprocess
  Automatizare  n8n, Docker
  Analiza       BeautifulSoup4, re, json

## Planuri de Dezvoltare

- Integrare cu Wazuh SIEM
- Interfata web pentru fiecare tool
- Automatizare completa cu n8n
- Adaugare SDR (radio)
- Cyberdeck portabil
- Eye Scanner

## Autor

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea
Email: mircearbt@gmail.com

---

*Proiect realizat ca parte a portofoliului de securitate cibernetica.*
