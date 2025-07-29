<h1 align="center">
  ![SenSIEM Dashboard](frontend/src/assets/Sensiem_Search.png)
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

### 📸 Screenshots

<p align="center">
  ![SenSIEM Dashboard](frontend/src/assets/Sensiem_Dashboard.png)
  
  <br />
  <em>Interactive dashboards with alert graphs and IP stats</em>
</p>

<p align="center">
  ![SenSIEM Dashboard](frontend/src/assets/Sensiem_Alerts.png)
  <br />
  <em>Interactive Alerts with alert graphs and IP stats</em>
</p>


---

### 🚀 Getting Started

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
