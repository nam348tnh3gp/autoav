# 🛡️ AutoAV – Real‑time Antivirus & Monitoring for Linux

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![ClamAV](https://img.shields.io/badge/ClamAV-Enabled-00d0a0?logo=clamav&logoColor=white)](https://www.clamav.net/)
[![YARA](https://img.shields.io/badge/YARA-Ready-00d0a0)](https://virustotal.github.io/yara/)

**AutoAV** is a fully‑automated, enterprise‑grade real‑time antivirus and monitoring system for Linux. It protects your server 24/7 by scanning file modifications and new files using **ClamAV** and **YARA** rules, isolates suspicious files into quarantine, and provides a clean **web dashboard** and **Webhook API** for alerts and manual scanning.  

All it takes is running one script – AutoAV installs everything, configures itself, and starts protecting your system immediately.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **📁 Real‑time file monitoring** | Uses `inotify` to instantly scan files when they are created or modified. |
| **🦠 Dual‑engine scanning** | Combines **ClamAV** signatures with **YARA** rules for maximum detection. |
| **🚫 Smart malware quarantine** | Isolates infected files, protects against symlink attacks, and checks disk space before moving. |
| **🗄️ SQLite database** | Stores all security events and malware detections for auditing. |
| **📊 Web dashboard** | Built with **Flask + Bootstrap**, accessible only from **localhost** by default (iptables/firewalld). |
| **🔌 Webhook API** | Secured with an **API token** to trigger manual scans or integrate with external tools. |
| **⚙️ Live configuration reload** | Send `SIGHUP` to the daemon to apply changes without restarting. |
| **🛡️ Self‑healing** | 
| **💾 Disk & space checks** | Monitors free space before quarantine and warns if low. |
| **🧹 Automatic cleanup** | Removes quarantined files older than 30 days via cron. |
| **📦 Supports all major distros** | Works on Debian, Ubuntu, CentOS, Rocky, AlmaLinux, Fedora, Arch, Manjaro, openSUSE. |

---

## 📋 System Requirements

- **Linux** distribution (systemd‑based)
- **Root access** (required for installation and firewall setup)
- **Internet connection** (to download ClamAV databases and dependencies)
- At least **2 GB RAM** recommended for active scanning

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/nam348tnh3gp/autoav.git
cd autoav
```

2. Run the installer

```bash
sudo bash autoav.sh
```

The script will:

· Detect your Linux distribution and package manager (apt, dnf, pacman, zypper).
· Install all dependencies: ClamAV, YARA (built from source), Python virtual environment, inotify-tools, iptables and more.
· Create a dedicated system user autoav with restricted privileges.
· Configure iptables / firewalld to block remote access to the dashboard (localhost‑only).
· Set up systemd services (autoav-daemon and autoav-dashboard) and start them automatically.
· Print the dashboard URL, API token, and a ready‑to‑use test command.

---

🔧 Configuration

Main configuration file

All settings are stored in /opt/auto_antivirus/av-core.yaml.

```yaml
watch_directories:
  - /home
  - /tmp
  - /var/www
  - /etc
  - /usr/bin
  - /dev/shm
  - /run/shm

exclude_paths:
  - /proc
  - /sys

max_file_size_mb: 100
clamd_socket: "/var/run/clamav/clamd.ctl"
yara_rule_file: "/opt/auto_antivirus/rules/malware.yar"
webhook_url: ""
quarantine_dir: "/opt/auto_antivirus/quarantine"
log_file: "/opt/auto_antivirus/logs/av.log"
db_path: "/opt/auto_antivirus/av.db"
dashboard_port: 5000
webhook_api_port: 5001
scan_debounce_seconds: 5
disk_usage_warning_percent: 10
watchdog_health_check_seconds: 60
quarantine_permission_check_seconds: 300
```

Custom YARA rules

You can add your own custom YARA rules in /opt/auto_antivirus/rules/malware.yar.
A minimal example rule is already provided in that file.

Firewall rules

· iptables: two rules are inserted
  ACCEPT from 127.0.0.1 on port 5000
  DROP on port 5000 from anywhere else
· firewalld: rich rules are added to the default zone
  (localhost allowed, others dropped)
· The rules are made permanent where possible.

After installation, you can verify the firewall configuration with:

```bash
iptables -L INPUT -v -n | grep 5000
```

or

```bash
firewall-cmd --list-rich-rules
```

---

🎮 Usage

View the dashboard

Open a browser on the same machine and go to:

```
http://127.0.0.1:5000
```

To access the dashboard remotely, set up an SSH tunnel:

```bash
ssh -L 5000:127.0.0.1:5000 user@your-server
```

Then open http://127.0.0.1:5000 on your local machine.

Send a file for manual scanning

Use the API token (printed during installation or stored in /etc/autoav_api_token):

```bash
curl -X POST http://127.0.0.1:5001/api/report \
  -H "X-API-Token: YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path": "/tmp/suspicious_file"}'
```

The daemon will immediately scan the specified file and quarantine it if malware is detected.

Reload configuration without restart

```bash
sudo systemctl reload autoav-daemon
```

View real‑time logs

```bash
tail -f /opt/auto_antivirus/logs/av.log
```

Stop / start services

```bash
sudo systemctl stop autoav-daemon
sudo systemctl start autoav-daemon
sudo systemctl restart autoav-dashboard
```

---

📊 Monitoring & Alerts

Webhook alerts

If you provide a webhook URL during installation, AutoAV will send JSON payloads to that endpoint for critical events:

· Malware detections – [CRITICAL] {threat} in {path}
· Low disk space – [WARNING] Disk space low on quarantine volume
· Quarantine permission errors – [ERROR] Quarantine directory not writable

The webhook endpoint must accept HTTP POST requests.

Dashboard UI

The dashboard displays:

· Recent malware detections (with filename, threat name, status, and manual quarantine button).
· Security events (file events, scan results, error messages).
· A manual scan form to trigger scanning of any file on the system.

---

🔄 Automatic maintenance

AutoAV includes several built‑in self‑care mechanisms:

Task Frequency Purpose
Log rotation Daily Keeps logs manageable (7 rotations).
Quarantine cleanup Daily Deletes quarantined files older than 30 days.
Disk space check Every 15 minutes Warns when free space falls below threshold.
Quarantine permission check Every 5 minutes Checks if quarantine directory is writable; attempts to auto‑fix if root.
Watchdog health check Every 60 seconds Restarts the inotify monitor if it crashes.

---

🐞 Troubleshooting

ClamAV socket not found

If the daemon fails to start because the ClamAV socket is missing:

```bash
sudo systemctl status clamav-daemon
sudo journalctl -u clamav-daemon
```

On some distributions (e.g., Arch Linux), you may need to enable the clamav-daemon service manually:

```bash
sudo systemctl enable --now clamav-daemon
```

The installer already waits up to 20 seconds for the socket to appear, but if ClamAV is misconfigured, you may need to adjust /etc/clamav/clamd.conf to use a LocalSocket path.

Dashboard unreachable

Make sure you are accessing the dashboard from localhost or using an SSH tunnel.
Check the firewall rules:

```bash
iptables -L INPUT -v -n | grep 5000
```

If you are using firewalld:

```bash
firewall-cmd --list-rich-rules
```

Permission errors on quarantine

If you see Quarantine directory not writable in the logs:

1. Check the directory permissions:
   ```bash
   ls -ld /opt/auto_antivirus/quarantine
   ```
   Expected output: drwxr-x--- ... autoav autoav
2. Manually fix them if needed:
   ```bash
   sudo chmod 750 /opt/auto_antivirus/quarantine
   sudo chown autoav:autoav /opt/auto_antivirus/quarantine
   ```

YARA compilation fails

YARA is built from source. Make sure you have the required build tools:

· Debian/Ubuntu: build-essential libtool autoconf automake pkg-config flex bison libjansson-dev libmagic-dev
· RHEL/CentOS: make gcc libtool autoconf automake pkgconfig flex bison jansson-devel file-devel
· Arch: base-devel libtool autoconf automake pkgconf flex bison jansson file

The installer will attempt to install these automatically.

---

🤝 Contributing

Contributions are welcome! Feel free to:

· Report bugs or suggest features via GitHub Issues
· Submit pull requests with improvements or bug fixes
· Share your custom YARA rules

Please ensure your code follows the existing style and passes basic shellcheck / pycodestyle checks.

---

📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

---

🙏 Acknowledgements

· ClamAV – the open‑source antivirus engine.
· YARA – the pattern matching tool for malware researchers.
· Flask and Bootstrap – for the lightweight web dashboard.
· inotify-tools – for efficient file system monitoring.

---

Made for Linux system administrators who want strong, silent, and self‑healing protection.
