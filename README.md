# Argus

Argus is a Python-based Discord ChatOps engine for security operations. It runs a Discord bot that receives SIEM webhook events, enriches threat data, and presents interactive incident response controls through Discord message components.

## What it does

- Listens for SIEM webhook POSTs at `/webhook` on port `5000`
- Parses incoming alert payloads and builds Discord embeds
- Enriches attacker IP data using AbuseIPDB when configured
- Loads Discord extension modules from `cogs/`
- Provides interactive buttons to block or dismiss alerts
- Uses SSH to orchestrate firewall actions on a target host via `ufw`
- Includes a scheduled threat intelligence extension that posts RSS feed summaries to Discord

## Installation

1. Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

2. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

3. Create a `.env` file in the project root and set required variables

## Required environment variables

- `DISCORD_BOT_TOKEN`
- `DISCORD_GENERAL_CHANNEL_ID`
- `DISCORD_THREAT_INTEL_CHANNEL_ID`
- `PWNEDBYJT_DISCORD_USER_ID`
- `PI_IP`
- `PI_USER`

## Optional environment variables

- `ABUSEIPDB_API_KEY` — enables external IP reputation lookups
- `BAN_DURATION_SECONDS` — temporary block duration, default `300`

## Run

```powershell
python argus.py
```

The bot starts Discord connection and launches the Flask webhook listener alongside it.

## Webhook interface

- Endpoint: `POST /webhook`
- Port: `5000`
- Payload: JSON containing a `rule` object and `data.srcip`

The webhook server accepts either a direct payload or a nested `all_fields` object and forwards processed alerts to the configured Discord channel.

## Notes

- The bot uses `discord.py` and Flask
- `cogs/threat_intel.py` implements a daily RSS feed collector for threat intelligence posts
- The bot dynamically loads all Python files in `cogs/` at startup

## Architecture

- The alert processing flow chart is available in `cogs/flowChart.mmd`
- The diagram covers:
  - Wazuh SIEM alert ingestion
  - Flask webhook enrichment and threat scoring
  - Discord alert card dispatch and analyst interaction
  - Paramiko SSH firewall enforcement and automatic unblock lifecycle

## Flow chart

```mermaid
flowchart TD
    subgraph SIEM["SIEM Environment — Wazuh"]
        A(["Wazuh SIEM · Anomaly Detected"])
        B[/"HTTP POST · JSON Alert Payload"/]
        A -->|"Brute force / File Read event"| B
    end

    subgraph FLASK["Flask Webhook API — Thread 1 · Port 5000"]
        C["Flask Webhook · Receives POST /alert"]
        D{"DLP Keyword Scan\n(PII / SSN)"}
        E["AbuseIPDB API · OSINT Threat Score"]
        F[/"Enriched Alert Payload"/]
        G["asyncio.run_coroutine_threadsafe()\nCross-thread handoff"]
        C --> D
        D -->|"Scan alert description"| E
        E -->|"Append threat score"| F
        D --> F
        F --> G
    end

    subgraph BOT["Discord Bot Engine — Thread 2 · asyncio Event Loop"]
        H["Build Interactive UI View & Alert Card"]
        I["WebSocket Dispatch to SOC Channel"]
        J{{"Analyst Reviews Alert Card"}}
        K["Dismiss · Disable UI\nLog as False Positive"]
        L["Block IP Selected"]
        M["asyncio.to_thread()\nParamiko SSH — off event loop"]
        N["Background Task · asyncio.sleep(300s)"]
        H --> I
        I --> J
        J -->|"Option A — False Positive"| K
        J -->|"Option B — Block IP"| L
        L --> M
        L --> N
    end

    subgraph PI["Target Endpoint — Raspberry Pi"]
        O["SSH Connection Established · Paramiko"]
        P[/"Execute: sudo ufw deny from Attacker_IP"/]
        Q["IP Blocked · Firewall Rule Active"]
        R["Lifecycle Timer Expires · 300 s"]
        S["SSH Reconnect · Paramiko"]
        T[/"Execute: sudo ufw delete deny"/]
        U["Block Lifted · Firewall Rule Removed"]
        O --> P
        P --> Q
        R --> S
        S --> T
        T --> U
    end

    V["Receipt Posted to SOC Channel\nTemporary block confirmed lifted"]

    B -->|"HTTP POST intercepted"| C
    G -->|"Coroutine passed to bot event loop"| H
    M -->|"SSH handoff — off event loop"| O
    N -->|"Timer expires"| R
    U --> V
    V --> BOT
```
