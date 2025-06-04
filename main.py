import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from scapy.all import rdpcap
from analyzers.dns_scanner import analyze_dns_packets
from analyzers.http_scanner import analyze_http_packets
from analyzers.icmp_scanner import analyze_icmp_packets
import os

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Analyzer")

        self.file_path = None

        # button to select the files
        self.file_label = tk.Label(root, text="No file selected", fg="blue")
        self.file_label.pack(pady=5)

        self.browse_button = tk.Button(root, text="Select PCAP File", command=self.browse_file)
        self.browse_button.pack()

        # select the scan types -> checkboxes 
        self.dns_var = tk.BooleanVar(value=True)
        self.http_var = tk.BooleanVar(value=True)
        self.icmp_var = tk.BooleanVar(value=True)

        self.checkbox_frame = tk.Frame(root)
        self.checkbox_frame.pack(pady=5)

        tk.Checkbutton(self.checkbox_frame, text="DNS", variable=self.dns_var).pack(side="left")
        tk.Checkbutton(self.checkbox_frame, text="HTTP", variable=self.http_var).pack(side="left")
        tk.Checkbutton(self.checkbox_frame, text="ICMP", variable=self.icmp_var).pack(side="left")

        self.scan_button = tk.Button(root, text="Scan", command=self.run_analysis)
        self.scan_button.pack(pady=5)

        # analysis result text box thing
        self.output_text = scrolledtext.ScrolledText(root, width=100, height=30)
        self.output_text.pack(padx=10, pady=10)

    def browse_file(self):
        filetypes = [("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        path = filedialog.askopenfilename(title="Select PCAP file", filetypes=filetypes)
        if path:
            self.file_path = path
            self.file_label.config(text=os.path.basename(path))

    def run_analysis(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a PCAP file.")
            return

        try:
            self.output_text.delete("1.0", tk.END)
            packets = rdpcap(self.file_path)

            # scan identifiers to separate blocks 
            if self.dns_var.get():
                self.output_text.insert(tk.END, "============== DNS Scan Results ==============\n")
                dns_results = analyze_dns_packets(packets)
                self.result_print(dns_results)

            if self.http_var.get():
                self.output_text.insert(tk.END, "============== HTTP Scan Results ==============\n")
                http_results = analyze_http_packets(packets)
                self.result_print(http_results)

            if self.icmp_var.get():
                self.output_text.insert(tk.END, "============== ICMP Scan Results ==============\n")
                icmp_results = analyze_icmp_packets(packets)
                self.result_print(icmp_results)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file:\n{e}")

    # printing function for tkinter text box (with the scan results)
    def result_print(self, results):
        if not results:
            self.output_text.insert(tk.END, "No significant findings.\n\n")
            return

        for key, value in results.items():
            self.output_text.insert(tk.END, f"{key}:\n")
            if isinstance(value, list):
                if not value:
                    self.output_text.insert(tk.END, "  (None)\n")
                else:
                    for idx, item in enumerate(value, 1):
                        self.output_text.insert(tk.END, f"  [{idx}]\n")
                        if isinstance(item, dict):
                            for k, v in item.items():
                                self.output_text.insert(tk.END, f"    {k}: {v}\n")
                        else:
                            self.output_text.insert(tk.END, f"    {item}\n")
            elif isinstance(value, dict):
                for subkey, subval in value.items():
                    self.output_text.insert(tk.END, f"  {subkey}: {subval}\n")
            else:
                self.output_text.insert(tk.END, f"  {value}\n")
            self.output_text.insert(tk.END, "-" * 60 + "\n")
        self.output_text.insert(tk.END, "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
