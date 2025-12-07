"""
Network Discovery Tool - Fixed Layout
This fixes the missing buttons issue by ensuring proper window sizing
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading

class NetworkDiscoveryWindow:
    def __init__(self, parent=None):
        self.window = tk.Toplevel(parent) if parent else tk.Tk()
        self.window.title("🔍 Network Discovery")
        self.window.geometry("650x550")  # Increased height to show all buttons
        self.window.minsize(600, 500)
        
        # Configure grid weights for proper resizing
        self.window.grid_rowconfigure(2, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_frame = tk.Frame(self.window, bg="#2e7d32", height=60)
        title_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        title_frame.grid_propagate(False)
        
        tk.Label(
            title_frame,
            text="🔍 Network Discovery",
            font=("Segoe UI", 16, "bold"),
            bg="#2e7d32",
            fg="white"
        ).pack(expand=True)
        
        tk.Label(
            title_frame,
            text="Scan your network to automatically discover devices",
            font=("Segoe UI", 9),
            bg="#2e7d32",
            fg="white"
        ).pack()
        
        # Parameters Frame
        params_frame = ttk.LabelFrame(self.window, text="Discovery Parameters", padding=10)
        params_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        
        # Subnet input
        tk.Label(params_frame, text="Subnet to scan (e.g., 192.168.1.0/24):").grid(
            row=0, column=0, sticky="w", pady=5
        )
        self.subnet_entry = tk.Entry(params_frame, width=40)
        self.subnet_entry.insert(0, "192.168.1.0/24")
        self.subnet_entry.grid(row=1, column=0, sticky="ew", pady=5)
        
        # Ports input
        tk.Label(params_frame, text="Common ports to check (comma-separated):").grid(
            row=2, column=0, sticky="w", pady=5
        )
        self.ports_entry = tk.Entry(params_frame, width=40)
        self.ports_entry.insert(0, "22,23,80,443")
        self.ports_entry.grid(row=3, column=0, sticky="ew", pady=5)
        
        params_frame.grid_columnconfigure(0, weight=1)
        
        # Results Frame
        results_frame = ttk.LabelFrame(self.window, text="Discovered Devices", padding=10)
        results_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=10,
            width=60,
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.results_text.grid(row=0, column=0, sticky="nsew")
        self.results_text.insert("1.0", "✅ Ready to scan!\n\n")
        self.results_text.insert("end", "Click 'Start scan' to begin network discovery.\n")
        self.results_text.insert("end", "Devices will appear here as they are found.\n")
        
        # Buttons Frame - THIS WAS THE MISSING PART!
        buttons_frame = tk.Frame(self.window)
        buttons_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        
        # Start Scan Button
        self.scan_button = tk.Button(
            buttons_frame,
            text="🔍 Start scan",
            command=self.start_scan,
            bg="#4CAF50",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=8,
            cursor="hand2"
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Stop Button
        self.stop_button = tk.Button(
            buttons_frame,
            text="⏹ Stop",
            command=self.stop_scan,
            bg="#f44336",
            fg="white",
            font=("Segoe UI", 10),
            padx=20,
            pady=8,
            state=tk.DISABLED,
            cursor="hand2"
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Import Inventory Button
        self.import_button = tk.Button(
            buttons_frame,
            text="📁 Import inventory",
            command=self.import_inventory,
            bg="#2196F3",
            fg="white",
            font=("Segoe UI", 10),
            padx=20,
            pady=8,
            cursor="hand2"
        )
        self.import_button.pack(side=tk.LEFT, padx=5)
        
        # Close Button
        self.close_button = tk.Button(
            buttons_frame,
            text="✖ Close",
            command=self.window.destroy,
            bg="#757575",
            fg="white",
            font=("Segoe UI", 10),
            padx=20,
            pady=8,
            cursor="hand2"
        )
        self.close_button.pack(side=tk.RIGHT, padx=5)
        
        self.scanning = False
        
    def start_scan(self):
        subnet = self.subnet_entry.get().strip()
        ports = self.ports_entry.get().strip()
        
        if not subnet:
            messagebox.showwarning("Input Required", "Please enter a subnet to scan")
            return
            
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert("1.0", f"🔍 Scanning {subnet}...\n\n")
        
        # Start scan in thread
        thread = threading.Thread(target=self.perform_scan, args=(subnet, ports), daemon=True)
        thread.start()
        
    def perform_scan(self, subnet, ports):
        """Simplified network scan"""
        try:
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
            
            # Extract base IP
            base_ip = ".".join(subnet.split("/")[0].split(".")[:-1]) + "."
            
            self.results_text.insert("end", "Scanning devices...\n\n")
            
            found_devices = 0
            for i in range(1, 255):
                if not self.scanning:
                    break
                    
                ip = f"{base_ip}{i}"
                
                # Quick ping-like check
                try:
                    socket.setdefaulttimeout(0.1)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((ip, 80))
                    sock.close()
                    
                    if result == 0:
                        found_devices += 1
                        self.results_text.insert("end", f"✅ Found: {ip}\n")
                        self.results_text.see(tk.END)
                        self.window.update()
                except:
                    pass
            
            self.results_text.insert("end", f"\n✅ Scan complete! Found {found_devices} device(s)\n")
            
        except Exception as e:
            self.results_text.insert("end", f"\n❌ Error: {str(e)}\n")
        finally:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
    def stop_scan(self):
        self.scanning = False
        self.results_text.insert("end", "\n⏹ Scan stopped by user\n")
        
    def import_inventory(self):
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select inventory file",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                self.results_text.delete("1.0", tk.END)
                self.results_text.insert("1.0", f"📁 Imported from: {filename}\n\n{content}")
                messagebox.showinfo("Success", f"Inventory imported from:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import file:\n{str(e)}")

if __name__ == "__main__":
    app = NetworkDiscoveryWindow()
    app.window.mainloop()
