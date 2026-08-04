# n8n Workflow – Automatizare Email

> Workflow n8n pentru categorisirea automată a emailurilor folosind un model LLM local (Ollama).

## Scop

Acest workflow face parte din homelab-ul meu și automatizează procesul de triere a emailurilor primite. Când un email nou ajunge în inbox, workflow-ul:
1. Citește conținutul emailului.
2. Trimite conținutul către un model LLM local (Ollama) pentru categorisire.
3. Salvează rezultatul într-un Google Sheet pentru revizuire umană.

## Tehnologii

- n8n (automatizare workflow)
- Ollama (LLM local, self-hosted)
- Google Sheets API
- Gmail API

## Workflow

Gmail Trigger → IF (filtrare spam) → Ollama API → Google Sheets


## Instalare

1. Asigură-te că n8n rulează (`docker start n8n`).
2. Asigură-te că Ollama rulează și modelul `llama3.2:3b` este instalat.
3. Importă workflow-ul în n8n (drag & drop fișierul `.json` în interfața n8n).
4. Configurează credentialele pentru:
   - Gmail (OAuth2)
   - Google Sheets (OAuth2)
   - Ollama (URL: `http://host.docker.internal:11434`)

## Utilizare

Workflow-ul rulează automat la fiecare 5 minute. Emailurile primite sunt procesate și adăugate în Google Sheet-ul configurat.