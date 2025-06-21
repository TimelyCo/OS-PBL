import tkinter as tk
from tkinter import messagebox
import sys
import os

# modules folder ka path jodhna padega
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'modules'))

from network_utils import NetworkUtilities

net_util = NetworkUtilities()

def run_scan():
    target = target_entry.get()
    ports = ports_entry.get()

    try:
        result = net_util.scan(target=target, ports=ports)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Scan Completed\n\n{result}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI window
root = tk.Tk()
root.title("Network Port Scanner")

tk.Label(root, text="Target IP:").grid(row=0, column=0, padx=10, pady=5)
target_entry = tk.Entry(root, width=30)
target_entry.grid(row=0, column=1, padx=10, pady=5)
target_entry.insert(0, "127.0.0.1")

tk.Label(root, text="Port Range (e.g., 20-25):").grid(row=1, column=0, padx=10, pady=5)
ports_entry = tk.Entry(root, width=30)
ports_entry.grid(row=1, column=1, padx=10, pady=5)
ports_entry.insert(0, "20-25")

tk.Button(root, text="Start Scan", command=run_scan).grid(row=2, column=0, columnspan=2, pady=10)

output_text = tk.Text(root, height=10, width=50)
output_text.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

root.mainloop()