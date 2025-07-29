<h1 align="center">
  <br>
  <span>SenSIEM</span> - Intrusion Detection & Log Monitoring Tool
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Project%20Status-80%25%20Complete-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/Tech-FastAPI%20%7C%20React-blue?style=flat-square" />
  <img src="https://img.shields.io/github/stars/chandruthehacker/sensiem?style=social" />
</p>

---

> 🚧 **Project Status: 80% Complete — Core System Functional!**
>
> ✅ Real-time detection, alert engine, dashboards, and notifications are working.  
> 🔧 Remaining: Rule editor, better UX, final cleanup & docs in progress.  
> 🛠️ SenSIEM is already practical and perfect for cybersecurity portfolios.

---

### 🛡️ What is SenSIEM?

**SenSIEM** is a modern, lightweight Security Information and Event Management (SIEM) system built for:

- 🔍 **Real-time log analysis**
- ⚡ **Intrusion detection**
- 📢 **Immediate alert notifications**
- 📊 **Visual dashboards & search filters**

Whether you're a **SOC analyst**, cybersecurity student, or blue teamer — this is a hands-on tool that mimics real-world detection workflows.

---

### ✨ Features

- 🔥 Live log ingestion with real-time alerting
- 🧠 Severity-based classification (Critical, High, Medium, Low)
- 🔍 Splunk-style query filters (`log_level=`, `source=`, `host=`, etc.)
- 📊 Dynamic dashboards (top IPs, alert breakdowns, log levels)
- 💬 Notifications to **Email**, **Slack**, **Telegram**
- 🧩 Modular structure (Frontend + Backend + Forwarder)
- 📁 Easily add log paths or ingest files
- 💾 SQLite/Postgres DB support for persistence

---

## 📂 SenSIEM Pages Overview

### 🔎 1. Search Page

<p align="center">
  <img src="frontend/src/assets/Sensiem_Search.png" alt="SenSIEM Search Page" width="700"/>
  <br />
  <em>Powerful search with Splunk-style filters and full-text log analysis</em>
</p>

- Search logs using filters like:
  - `from_host="192.168.0.5"`
  - `log_level="error"`
  - `source="sshd"`
  - Any keyword or phrase like `unauthorized`, `aborted`, etc.
- Combine filters for precise log discovery
- Click to view full log details

---

### 📊 2. Dashboard Page

<p align="center">
  <img src="frontend/src/assets/Sensiem_Dashboard.png" alt="SenSIEM Dashboard" width="700"/>
  <br />
  <em>Interactive visual dashboards with alert trends, IP stats, log levels, and more</em>
</p>

- Displays:
  - Top source IPs
  - Alerts over time
  - Log level breakdowns
  - Suspicious login attempts
- Updated dynamically from the backend

---

### 📄 3. Logs Page

<p align="center">
  <img src="frontend/src/assets/Sensiem_Logs.png" alt="SenSIEM Logs Page" width="700"/>
  <br />
  <em>Complete log stream view with quick access to any entry</em>
</p>

- View all ingested logs in chronological order
- Click on each log to expand full details
- Shows timestamp, log level, source, and more

---

### 🚨 4. Alerts Page

<p align="center">
  <img src="frontend/src/assets/Sensiem_Alerts.png" alt="SenSIEM Alerts Page" width="700"/>
  <br />
  <em>Severity-filtered alerts with detailed threat detection info</em>
</p>

- Auto-detected alerts based on:
  - Suspicious log patterns
  - Failed logins
  - Brute-force attempts
- Severity categories: Critical, High, Medium, Low
- Integrated alert rules with real-time trigger system

---

### ⚙️ 5. Settings Page

<p align="center">
  <img src="frontend/src/assets/Sensiem_Settings.png" alt="SenSIEM Settings Page" width="700"/>
  <br />
  <em>Manage log paths, configure notifications, and backup settings</em>
</p>

- Add/remove log folders to monitor
- Test and configure notification channels:
  - Email
  - Slack
  - Telegram
- Save/load backup settings
- Update destination backend IP and port

---

## 🚀 Getting Started

```bash
# 1. Clone the repo
git clone https://github.com/chandruthehacker/Sensiem.git
cd sensiem

# 2. Backend setup (FastAPI)
cd backend
pip install -r requirements.txt
python run.py

# 3. Frontend setup (Next.js + Tailwind)
cd ../frontend
npm install
npm run dev
