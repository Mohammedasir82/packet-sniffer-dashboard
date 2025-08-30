# 🕵️ Packet Sniffer Dashboard  

A Python-based packet sniffer with a **Flask web dashboard** to visualize captured network traffic in real time.  
It captures packets, stores them in a database, and presents insights like protocol distribution, top IPs, and recent packet logs.  

> [!NOTE]  
> This project is for **educational and research purposes only**.  
> Do not use it for unauthorized monitoring of networks.  

---

## 📌 Features  
- Real-time packet capture using **Scapy/Npcap**  
- Stores captured packets into **SQLite database**  
- **Flask dashboard** with:  
  - Protocol distribution pie chart  
  - Top source & destination IPs  
  - Recent packets table with filtering  
- Export captured data as CSV  

---

## 📖 Prerequisites  
1. **Python 3.10+** recommended  
2. Install dependencies from `requirements.txt`  
3. **Npcap/WinPcap** (on Windows) or **root privileges** (Linux) for packet sniffing  
4. Browser (Chrome/Firefox) to access the dashboard  

---
## ⚙️ Setup  

```bash
# Clone the repository
git clone https://github.com/your-username/packet-sniffer-dashboard.git
cd packet-sniffer-dashboard

# Setup virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

#call this 
python sniffer.py

#call this 
python dashboard.py

#Finally open in browser that showed in your python dashboard.py


