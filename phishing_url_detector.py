import tkinter as tk
from tkinter import messagebox
import requests
import json
import webbrowser

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

# Your VirusTotal API key
VIRUSTOTAL_API_KEY = 'Input Your VirusTotal API Key in here'

window = tk.Tk()
window.title("Phishing URL Scanner")
window.geometry("500x300")
window.configure(bg="#ffffff")
url_label = tk.Label(window, text="Enter URL to scan:", font=("Helvetica", 14), fg="#2c3e50", bg="#ffffff")
url_label.pack(pady=10)
url_entry = tk.Entry(window, font=("Helvetica", 14), fg="#2c3e50", bg="#ecf0f1", width=40)
url_entry.pack(pady=10)

def on_scan_clicked():
    scan_text.configure(state='normal')
    scan_text.delete('1.0', tk.END)
    url = url_entry.get()
    is_phishing = scan_url_virustotal(url)
    
    if is_phishing:
        result_label.config(text=f"{url} is a phishing website.", fg='#e74c3c')
        show_warning_messagebox(url)
    else:
        result_label.config(text=f"{url} is a safe website.", fg='#0e6251')
        webbrowser.open(url)
    
    scan_text.configure(state='disabled')

scan_button = tk.Button(window, text="Scan URL", font=("Helvetica", 14), fg="#ffffff", bg="#2c3e50", activebackground="#34495e", activeforeground="#ffffff", borderwidth=0, padx=20, pady=10, command=on_scan_clicked)
scan_button.pack(pady=20)
result_label = tk.Label(window, text="", font=("Helvetica", 14), fg="#2c3e50", bg="#ffffff")
result_label.pack(pady=10)
scan_text = tk.Text(window, font=("Helvetica", 12), fg="#2c3e50", bg="#ecf0f1", width=60, height=5, state='disabled')
scan_text.pack(pady=10)


def scan_url_virustotal(url):
    response = requests.get(VIRUSTOTAL_URL, params={'apikey': VIRUSTOTAL_API_KEY, 'resource': url})
    json_response = json.loads(response.text)
    is_phishing = False
    if json_response['response_code'] == 1:
        if json_response['positives'] > 0:
            is_phishing = True
            
    return is_phishing

def show_warning_messagebox(url):
    messagebox.showwarning(title="Phishing URL Detected", message=f"{url} has been identified as a phishing website. Please do not proceed to this website.")
window.mainloop()
