import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
from collections import Counter
import matplotlib.pyplot as plt
import threading
import time
import socket

# Global counters
protocol_counter = Counter()
ip_counter = Counter()
suspicious_ips = set()
capturing = False

# Thresholds
DOS_THRESHOLD = 50  # packets per IP in short time

# Main packet analysis
def analyze_packet(packet):
    if not packet.haslayer('IP'):
        return

    ip_layer = packet['IP']
    src = ip_layer.src
    proto = ip_layer.proto

    ip_counter[src] += 1

    if proto == 6:
        protocol_counter['TCP'] += 1
    elif proto == 17:
        protocol_counter['UDP'] += 1
    elif proto == 1:
        protocol_counter['ICMP'] += 1
    else:
        protocol_counter[str(proto)] += 1

    # DoS detection
    if ip_counter[src] > DOS_THRESHOLD:
        suspicious_ips.add(src)

# Capture thread
def start_sniff():
    global capturing
    capturing = True
    sniff(prn=analyze_packet, store=0, stop_filter=lambda x: not capturing)

# GUI update thread
def update_output():
    while capturing:
        output_text.delete("1.0", tk.END)

        output_text.insert(tk.END, "📊 Protocols:\n")
        for proto, count in protocol_counter.items():
            output_text.insert(tk.END, f"  {proto}: {count}\n")

        output_text.insert(tk.END, "\n📶 Top IPs:\n")
        for ip, count in ip_counter.most_common(5):
            output_text.insert(tk.END, f"  {ip}: {count}\n")

        if suspicious_ips:
            output_text.insert(tk.END, "\n🚨 Suspicious IPs:\n")
            for ip in suspicious_ips:
                output_text.insert(tk.END, f"  ⚠️ {ip} (High traffic)\n")

        time.sleep(2)

# Start capture button
def start_capture():
    global capture_thread, update_thread
    protocol_counter.clear()
    ip_counter.clear()
    suspicious_ips.clear()
    output_text.delete("1.0", tk.END)

    capture_thread = threading.Thread(target=start_sniff, daemon=True)
    update_thread = threading.Thread(target=update_output, daemon=True)

    capture_thread.start()
    update_thread.start()

# Stop capture button
def stop_capture():
    global capturing
    capturing = False
    output_text.insert(tk.END, "\n🛑 Capture stopped.\n")

# Show protocol pie chart
def show_chart():
    if not protocol_counter:
        return
    labels = list(protocol_counter.keys())
    sizes = list(protocol_counter.values())

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%')
    plt.title("Protocol Distribution")
    plt.axis("equal")
    plt.show()

# GUI setup
root = tk.Tk()
root.title("Network Traffic Analyzer")
root.geometry("500x500")

tk.Button(root, text="▶ Start Capture", command=start_capture, width=20).pack(pady=10)
tk.Button(root, text="⏹ Stop Capture", command=stop_capture, width=20).pack()
tk.Button(root, text="📈 Show Chart", command=show_chart, width=20).pack(pady=10)

output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20, font=("Consolas", 10))
output_text.pack(pady=10)

root.mainloop()
