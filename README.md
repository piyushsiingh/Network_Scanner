# 🌐 Python Network Scanner

> 🚨 **Disclaimer:** This tool is for **educational** and **authorized use only**. Unauthorized scanning of networks is illegal and unethical.

---

## 📌 1. Project Overview

### 1.1 Description

A **multi-threaded network scanner** written in Python that:
- Performs a **ping sweep** over a given subnet (CIDR)
- Detects **live hosts**
- Scans for **open ports** and identifies services
- Retrieves **MAC addresses**
- Generates a detailed **scan report** in `.txt` format

---

## 🚀 2. Features

- ⚡ Fast scanning using multithreading
- 🌐 CIDR-based network scanning (e.g., `192.168.1.0/24`)
- 📶 Live host detection via ping
- 🔍 Port scanning with customizable port list
- 💻 MAC address retrieval using `arp`
- 📊 Generates human-readable scan reports
- 🧠 Cross-platform compatibility (Windows, Linux, macOS)

---

## ⚙️ 3. Installation

### 3.1 Requirements
- Python 3.6 or higher
- No third-party libraries required (uses standard library)

### 3.2 Setup

```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
python scanner.py --help
```

---

## 🧪 4. Usage

### Basic Command

```bash
python scanner.py <network_cidr>
```

### Optional Arguments

| Flag | Description | Example |
|------|-------------|---------|
| `-p`, `--ports` | Comma-separated ports to scan | `-p 22,80,443` |
| `-t`, `--threads` | Number of concurrent threads | `-t 50` |
| `-o`, `--output` | File name for the scan report | `-o scan_results.txt` |

### Example

```bash
python scanner.py 192.168.1.0/24 -p 22,80 -t 100 -o my_report.txt
```

---

## 📁 5. Output

The tool creates a report like this in a `.txt` file:

```
Network Scan Report - 2025-07-15 14:32:10
Network: 192.168.1.0/24
==================================================

Host: 192.168.1.5
MAC Address: AA:BB:CC:DD:EE:FF
Open Ports:
  - Port 22: ssh
  - Port 80: http
```

---

## 🛡️ 6. Ethical Usage

- ✅ Use only on networks you **own** or have **explicit permission** to scan.
- ⚠️ Do **not** use for malicious or unauthorized activities.
- 👨‍💻 Ideal for:
  - Cybersecurity students
  - Network administrators
  - Pen-testing in safe environments

---

## 👨‍💻 7. Author

**Piyush Singh**  
🎓 Vivekananda Global University, Jaipur  
📧 [piyush.siingh2005@gmail.com](mailto:piyush.siingh2005@gmail.com)  
🔗 [GitHub](https://github.com/piyushsiingh)  
🔗 [LinkedIn](https://www.linkedin.com/in/piyush-singh-0b276332a)  
🌐 [Portfolio](https://bento.me/piyushsiingh)

---

## 📜 8. License

This project is licensed under the **MIT License**.  
See [LICENSE](LICENSE) for details.

---

## 🙏 9. Acknowledgements

- Python Standard Library
- Networking concepts & documentation
- Open source communities for inspiration
