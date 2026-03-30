import customtkinter as ctk
import pandas as pd
import os

# SETTINGS: Path to your realtime logs
LOG_DIR = os.path.join("..", "realtime") 
ALL_LOGS = os.path.join(LOG_DIR, "all_logs.csv")
ANOMALY_LOGS = os.path.join(LOG_DIR, "anomaly_logs.csv")
ALERT_LOGS = os.path.join(LOG_DIR, "alerts.csv")

ctk.set_appearance_mode("dark")

class IDSDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ShieldAI Dashboard")
        self.geometry("1000x600")

        # Grid config
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="IDS MONITOR", font=("Impact", 24)).pack(pady=20)

        # Stats
        self.total_lbl = self.create_card("TOTAL FLOWS", "0", "#008000")
        self.alert_lbl = self.create_card("ATTACKS", "0", "#FF5555")
        self.anomaly_lbl = self.create_card("SUSPICIOUS (ISO)", "0", "#FFBB33")

        # Main View
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.tabs.add("Live Alerts")
        self.tabs.add("Full History")
        self.tabs.add("Suspicious (ISO)")

        self.alert_box = ctk.CTkTextbox(self.tabs.tab("Live Alerts"), font=("Consolas", 12))
        self.alert_box.pack(fill="both", expand=True)

        self.anomaly_box = ctk.CTkTextbox(self.tabs.tab("Suspicious (ISO)"), font=("Consolas", 12))
        self.anomaly_box.pack(fill="both", expand=True)

        self.history_box = ctk.CTkTextbox(self.tabs.tab("Full History"), font=("Consolas", 11))
        self.history_box.pack(fill="both", expand=True)

        self.update_loop()

    def create_card(self, title, value, color):
        f = ctk.CTkFrame(self.sidebar, fg_color="#2B2B2B")
        f.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(f, text=title).pack()
        lbl = ctk.CTkLabel(f, text=value, font=("Arial", 32, "bold"), text_color=color)
        lbl.pack()
        return lbl

    def update_loop(self):
        try:
            # 1. Update Total Flows & History
            if os.path.exists(ALL_LOGS):
                df = pd.read_csv(ALL_LOGS)
                self.total_lbl.configure(text=str(len(df)))
                self.history_box.delete("1.0", "end")
                self.history_box.insert("end", df.tail(15).to_string(index=False))

            # 2. Update Alerts
            if os.path.exists(ALERT_LOGS):
                df_a = pd.read_csv(ALERT_LOGS)
                self.alert_lbl.configure(text=str(len(df_a)))
                self.alert_box.delete("1.0", "end")
                self.alert_box.insert("end", "!!! ATTACK LOGS !!!\n\n")
                self.alert_box.insert("end", df_a.tail(10).to_string(index=False))

            # 3. Update Anomaly Logs (Isolation Forest)
            if os.path.exists(ANOMALY_LOGS):
                df_iso = pd.read_csv(ANOMALY_LOGS)
                self.anomaly_lbl.configure(text=str(len(df_iso)))
                self.anomaly_box.delete("1.0", "end")
                self.anomaly_box.insert("end", "??? SUSPICIOUS ACTIVITY (ISO FOREST) ???\n\n")
                self.anomaly_box.insert("end", df_iso.tail(10).to_string(index=False))

        except Exception as e:
            print(f"Syncing for logs... {e}")

        self.after(2000, self.update_loop)

if __name__ == "__main__":
    app = IDSDashboard()
    app.mainloop()
