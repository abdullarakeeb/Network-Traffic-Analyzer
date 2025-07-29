# 🔎 Network Traffic Analyzer

A real-time network monitoring tool built with **Python**, **Scapy**, and **Tkinter**. This project captures and analyzes live network traffic, identifies top protocols and IPs, and flags suspicious behavior (e.g., potential DoS attacks) using customizable thresholds.

---

## 🛠 Features

- 📡 Real-time **packet sniffing** using Scapy
- 📊 Live display of:
  - Protocol usage (TCP, UDP, ICMP)
  - Top 5 IP addresses by traffic
  - 🚨 Suspicious IP detection based on traffic threshold
- 🖥️ GUI interface built with **Tkinter**
- 📈 Protocol distribution chart using **matplotlib**
- 🔐 Ideal for learning **network forensics**, **blue team operations**, and **packet analysis**

---

📚 Skills Demonstrated

Network Packet Analysis (Scapy)

Python GUI Design (Tkinter)

Data Visualization (Matplotlib)

Intrusion Detection Concepts

Multithreading in Python

---
## 🚀 How to Run

🧰 Requirements
Python 3.7+

Npcap (Windows) for packet sniffing: https://npcap.com/#download

Run with admin/root permissions for full packet access


### 📦 Install dependencies:

```bash
pip install scapy matplotlib
