<h1 align="center">

  <strong><b>👁 SenSIEM</b></strong>
</h1>


  <img src="https://raw.githubusercontent.com/chandruthehacker/Sensiem/main/frontend/src/assets/SenSIEM.png" alt="SenSIEM Logo" align="center"/>
<p align="center">
  <img src="https://img.shields.io/badge/Project%20Status-80%25%20Complete-yellow?style=flat-square" alt="Project Status" />
  <img src="https://img.shields.io/badge/Tech-FastAPI%20%7C%20React-blue?style=flat-square" alt="Tech Stack" />
  <img src="https://img.shields.io/github/stars/chandruthehacker/sensiem?style=social" alt="GitHub Stars" />
</p>

---

> ⚠️ **Work in Progress:**  
> ✅ Core modules are working (log analysis, dashboards, alerts, notifications).  
> 🧠 Final steps: rule editor, UX polish, documentation cleanup.  
> 🎯 Ideal for cybersecurity students and aspiring SOC analysts.

---

## 🛡️ What is SenSIEM?

**SenSIEM** (Security Event Notification + SIEM) is a modular, real-time Security Information and Event Management (SIEM) platform built for:

- 🔍 **Log analysis and search with filters**
- ⚠️ **Intrusion detection and alerting**
- 📊 **Interactive dashboards and trends**
- 💬 **Multi-channel alert notifications**

This project is **portfolio-ready** and simulates a mini-SOC environment — perfect for blue-team enthusiasts, analysts, and learners.

---

## 🚀 Features

### 🔍 Log Search (Splunk-like)
- Filter logs by log level, IP address, username, source, and time range
- Supports smart query syntax and alias matching
- View full log details in an interactive expandable dialog

### 📊 Dashboards
- Visual charts for log levels, alerts, suspicious IPs, and sources
- Auto-refreshing dashboards with drill-down capabilities

### 📁 Logs Viewer
- Complete view of ingested logs with quick filter chips
- Supports custom ingestion with dynamic log type detection

### 🚨 Alerts
- Real-time alerts triggered by detection rules (e.g., brute force, failed logins)
- Color-coded severity levels with timestamp and log source linkage
- Alert details dialog with scrollable context

### ⚙️ Settings
- Configure monitored paths or ingest files manually
- Manage detection rules, thresholds, and alert frequency
- Set up notification preferences (Email, Slack, Telegram)

---

## 🧠 Built-in Detection Rules

- 🔐 Brute-force login detection
- 🧑‍💻 Failed login spike alerts
- 📊 Anomaly detection based on log frequency
- 📈 Suspicious IP or geo-location monitoring

Rules run continuously and can be fine-tuned per log type, time window, and threshold.

---

## 🧱 Architecture Overview

```plaintext
          ┌────────────┐
          │  Forwarder │   (coming soon)
          └────┬───────┘
               ▼
     ┌───────────────────┐
     │   FastAPI Backend │ ◀── Rules Engine & DB
     └────────┬──────────┘
              ▼
     ┌──────────────────────┐
     │  React + Tailwind UI │ ◀── Log Viewer, Dashboards
     └──────────────────────┘
```

---

## 🚀 Quick Start

```bash
# Clone the project
git clone https://github.com/chandruthehacker/Sensiem.git
cd Sensiem

# Setup Backend (FastAPI)
cd backend
pip install -r requirements.txt
python run.py

# Setup Frontend (Next.js + Tailwind)
cd ../frontend
npm install
npm run dev
```

---

## 📽️ Demo (Coming Soon...)

🎥 Want to see it in action? Stay tuned for a YouTube demo and deployment tutorial!

---

## 🧠 Ideal For

- ✅ SOC Analyst Portfolio Projects  
- 🔐 Red/Blue Team Tooling  
- 📝 Log Analysis Learning  
- 🏠 Customizable Home-Lab SIEM Deployments

---

## 📄 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Pull requests, feedback, and feature suggestions are welcome!  
Let’s build a powerful open-source SIEM together.

---

## 🙌 Acknowledgements

Big thanks to:

- 🧬 The **FastAPI** and **React** communities  
- 📚 Cybersecurity writeups and bloggers  
- 💖 Everyone contributing to open-source tech
