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


## 🚀 How to Run

### 📦 Install dependencies:

```bash
pip install scapy matplotlib
