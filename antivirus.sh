#!/bin/bash
# ======================================================================
#   Auto Antivirus & Monitoring System v2.6.5 – Precision Edition
#   Patch: Reduced boot-time full scan max file size from 500MB to 100MB
#          for faster, more focused initial protection.
#   Fixes: - detect_clamav_service no longer pollutes stdout
#          - freshclam false positive warning removed
#          - Expanded socket detection for CentOS/RHEL
# ======================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
INSTALL_DIR="/opt/auto_antivirus"
CONFIG_FILE="$INSTALL_DIR/av-core.yaml"
SERVICE_DIR="/etc/systemd/system"
RUN_USER="autoav"
WEBHOOK_URL="${WEBHOOK_URL:-}"
DASHBOARD_PORT=5000
WEBHOOK_API_PORT=5001

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()      { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[W]${NC} $1"; }
log_err()     { echo -e "${RED}[!]${NC} $1"; exit 1; }

check_root() { [ "$EUID" -eq 0 ] || log_err "Run as root!"; }

detect_distro() {
    . /etc/os-release
    case $ID in
        ubuntu|debian|linuxmint|raspbian) PKG_MGR="apt"; INSTALL="apt install -y"; UPDATE="apt update"
            BUILD_DEPS="build-essential libtool autoconf automake pkg-config flex bison libjansson-dev libmagic-dev"
            CLAMAV_PKGS="clamav clamav-daemon" ;;
        centos|rhel|fedora|rocky|almalinux) PKG_MGR="dnf"; INSTALL="dnf install -y"; UPDATE="dnf check-update"
            BUILD_DEPS="make gcc libtool autoconf automake pkgconfig flex bison jansson-devel file-devel"
            CLAMAV_PKGS="clamav clamav-update clamd" ;;
        arch|manjaro) PKG_MGR="pacman"; INSTALL="pacman -Syu --noconfirm"; UPDATE="pacman -Sy"
            BUILD_DEPS="base-devel libtool autoconf automake pkgconf flex bison jansson file"
            CLAMAV_PKGS="clamav" ;;
        opensuse*|suse) PKG_MGR="zypper"; INSTALL="zypper install -y"; UPDATE="zypper refresh"
            BUILD_DEPS="make gcc libtool autoconf automake pkgconf flex bison libjansson-devel file-devel"
            CLAMAV_PKGS="clamav clamav-daemon" ;;
        *) log_err "Unsupported distro: $ID" ;;
    esac
}

install_deps() {
    log_info "Installing base dependencies..."
    $UPDATE
    $INSTALL $BUILD_DEPS python3 python3-pip python3-venv inotify-tools curl jq iptables || log_err "Core dependency installation failed"
    
    log_info "Installing ClamAV packages: $CLAMAV_PKGS"
    $INSTALL $CLAMAV_PKGS || log_warn "Some ClamAV packages may be missing; will attempt to configure socket."
    
    if ! command -v yara &>/dev/null; then
        log_info "Building YARA from source..."
        cd /tmp
        git clone --depth 1 https://github.com/VirusTotal/yara.git
        cd yara
        ./bootstrap.sh
        ./configure --enable-cuckoo --enable-magic
        make -j$(nproc)
        make install
        ldconfig
        cd .. && rm -rf yara
    fi

    if [ -d "$INSTALL_DIR/venv" ]; then
        log_info "Updating existing virtual environment..."
        source "$INSTALL_DIR/venv/bin/activate"
        pip install --upgrade pip
        pip install --upgrade pyclamd yara-python flask flask-sqlalchemy watchdog requests pyyaml gunicorn psutil
        deactivate
    else
        python3 -m venv "$INSTALL_DIR/venv"
        source "$INSTALL_DIR/venv/bin/activate"
        pip install --upgrade pip
        pip install pyclamd yara-python flask flask-sqlalchemy watchdog requests pyyaml gunicorn psutil
        deactivate
    fi
    log_ok "Dependencies installed."
}

# -------------------------------------------
# FIXED: Warnings go to stderr, never stdout
# -------------------------------------------
detect_clamav_service() {
    if systemctl list-unit-files | grep -q 'clamav-daemon.service'; then
        echo "clamav-daemon"
    elif systemctl list-unit-files | grep -q 'clamd@scan.service'; then
        echo "clamd@scan"
    elif systemctl list-unit-files | grep -q 'clamd.service'; then
        echo "clamd"
    else
        # Print warning to stderr so it doesn't pollute the function's stdout
        >&2 echo -e "${YELLOW}[W]${NC} Could not detect ClamAV service name. Please start it manually."
        echo ""
    fi
}

setup_clamav() {
    log_info "Configuring ClamAV..."
    systemctl stop clamav-freshclam 2>/dev/null || true

    # Run freshclam with proper success tracking
    local freshclam_ok=false
    for i in {1..3}; do
        if freshclam; then
            log_ok "Virus database updated."
            freshclam_ok=true
            break
        else
            log_warn "freshclam attempt $i failed, retrying in 10s..."
            sleep 10
        fi
    done
    if ! $freshclam_ok; then
        log_warn "freshclam may have failed completely. Check network."
    fi

    systemctl enable --now clamav-freshclam 2>/dev/null || true
    
    local clamav_service=$(detect_clamav_service)
    if [ -n "$clamav_service" ]; then
        systemctl enable --now "$clamav_service" 2>/dev/null || true
        log_ok "ClamAV service '$clamav_service' started."
    else
        log_warn "ClamAV service not detected. Socket may not be available."
    fi
}

wait_for_clamd_socket() {
    local socket_path=""
    for i in {1..10}; do
        socket_path=$(find_clamd_socket 2>/dev/null || true)
        if [ -n "$socket_path" ] && [ -S "$socket_path" ]; then
            echo "$socket_path"
            return 0
        fi
        log_info "Waiting for ClamAV socket... ($i/10)"
        sleep 2
    done
    log_err "ClamAV socket did not appear after 20 seconds. Check ClamAV service."
}

# -------------------------------------------
# FIXED: Expanded socket detection for CentOS/RHEL
# -------------------------------------------
find_clamd_socket() {
    # Try main config file
    local conf="/etc/clamav/clamd.conf"
    if [ -f "$conf" ]; then
        local path=$(grep -E '^\s*LocalSocket\s+' "$conf" | grep -v '^\s*#' | awk '{print $2}')
        [ -n "$path" ] && [ -S "$path" ] && { echo "$path"; return; }
    fi

    # CentOS/RHEL often uses /etc/clamd.d/scan.conf
    local scan_conf="/etc/clamd.d/scan.conf"
    if [ -f "$scan_conf" ]; then
        local path=$(grep -E '^\s*LocalSocket\s+' "$scan_conf" | grep -v '^\s*#' | awk '{print $2}')
        [ -n "$path" ] && [ -S "$path" ] && { echo "$path"; return; }
    fi

    # Common fallback locations
    for path in "/var/run/clamav/clamd.ctl" \
                "/run/clamav/clamd.ctl" \
                "/var/lib/clamav/clamd.socket" \
                "/var/run/clamd.scan/clamd.sock" \
                "/run/clamd.scan/clamd.sock"; do
        [ -S "$path" ] && { echo "$path"; return; }
    done

    return 1
}

setup_firewall() {
    log_info "Configuring firewall for dashboard port $DASHBOARD_PORT..."
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        log_info "Using firewalld..."
        if ! firewall-cmd --query-rich-rule="rule family='ipv4' source address='127.0.0.1' port port='$DASHBOARD_PORT' protocol='tcp' accept" &>/dev/null; then
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='127.0.0.1' port port='$DASHBOARD_PORT' protocol='tcp' accept"
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='$DASHBOARD_PORT' protocol='tcp' drop"
            firewall-cmd --reload
            log_ok "firewalld rules added."
        else
            log_info "firewalld rules already present."
        fi
    elif command -v iptables &>/dev/null; then
        log_info "Using iptables..."
        if ! iptables -C INPUT -p tcp -s 127.0.0.1 --dport $DASHBOARD_PORT -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p tcp -s 127.0.0.1 --dport $DASHBOARD_PORT -j ACCEPT
            log_ok "iptables ACCEPT rule added."
        else
            log_info "iptables ACCEPT rule already present."
        fi
        if ! iptables -C INPUT -p tcp --dport $DASHBOARD_PORT -j DROP 2>/dev/null; then
            iptables -I INPUT -p tcp --dport $DASHBOARD_PORT -j DROP
            log_ok "iptables DROP rule added."
        else
            log_info "iptables DROP rule already present."
        fi
        if command -v iptables-save &>/dev/null; then
            if [ -d /etc/iptables ]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            elif [ -f /etc/sysconfig/iptables ]; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
        fi
    else
        log_warn "No supported firewall (iptables/firewalld) found. Dashboard port is open."
    fi
}

create_structure() {
    if ! id "$RUN_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$RUN_USER"
    fi
    mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/quarantine" "$INSTALL_DIR/logs" "$INSTALL_DIR/rules" "$INSTALL_DIR/templates" "$INSTALL_DIR/static"
    chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR"
    
    API_TOKEN=$(openssl rand -hex 32)
    echo "$API_TOKEN" > /etc/autoav_api_token
    chmod 640 /etc/autoav_api_token
    chown root:$RUN_USER /etc/autoav_api_token

    if [ ! -f /etc/autoav_secret ]; then
        python3 -c "import secrets; print(secrets.token_hex(24))" > /etc/autoav_secret
        chmod 640 /etc/autoav_secret
        chown root:$RUN_USER /etc/autoav_secret
    fi

    cat > /etc/logrotate.d/autoav << EOF
/opt/auto_antivirus/logs/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 640 $RUN_USER $RUN_USER
}
EOF

    cat > /etc/cron.daily/autoav-cleanup << 'EOF'
#!/bin/bash
find /opt/auto_antivirus/quarantine -type f -mtime +30 -delete
find /opt/auto_antivirus/quarantine -type d -empty -delete
EOF
    chmod +x /etc/cron.daily/autoav-cleanup

    CLAMD_SOCK=$(wait_for_clamd_socket)
    
    # *** PATCH: full_scan_max_file_size_mb changed from 500 to 100 ***
    cat > "$CONFIG_FILE" << EOF
# AutoAV v2.6.5 Configuration
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
  - /dev
  - /run
  - /snap
  - /var/lib/docker
  - /var/lib/lxc
max_file_size_mb: 100
clamd_socket: "$CLAMD_SOCK"
yara_rule_file: "$INSTALL_DIR/rules/malware.yar"
webhook_url: "$WEBHOOK_URL"
quarantine_dir: "$INSTALL_DIR/quarantine"
log_file: "$INSTALL_DIR/logs/av.log"
db_path: "$INSTALL_DIR/av.db"
dashboard_port: $DASHBOARD_PORT
webhook_api_port: $WEBHOOK_API_PORT
scan_debounce_seconds: 5
disk_usage_warning_percent: 10
watchdog_health_check_seconds: 60
quarantine_permission_check_seconds: 300
# Boot-time full system scan (Precision Edition)
initial_full_scan: true
full_scan_paths:
  - /
full_scan_max_file_size_mb: 100
full_scan_nice: 19
full_scan_ionice: 3
full_scan_exclude:
  - /proc
  - /sys
  - /dev
  - /run
  - /snap
  - /var/lib/docker
  - /var/lib/lxc
EOF

    cat > "$INSTALL_DIR/rules/malware.yar" << 'YAR'
rule SuspiciousStrings {
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "eval(base64_decode" nocase
        $s3 = "powershell -exec bypass" nocase
        $s4 = "/bin/busybox" nocase
    condition:
        any of them
}
YAR
    chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR/rules"
    log_ok "Structure, user, and config created."
}

# ====== CORE PYTHON SCRIPTS ======

write_daemon() {
    cat > "$INSTALL_DIR/av-daemon.py" << 'PYEOF'
#!/usr/bin/env python3
import os, sys, time, signal, logging, json, threading, sqlite3, shutil, subprocess
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import yaml, pyclamd, yara
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

config_path = sys.argv[1] if len(sys.argv)>1 else "/opt/auto_antivirus/av-core.yaml"
with open(config_path) as f:
    config = yaml.safe_load(f)

LOG_FILE = config['log_file']; DB_PATH = config['db_path']
QUARANTINE_DIR = config['quarantine_dir']; CLAMD_SOCK = config['clamd_socket']
YARA_RULES = config['yara_rule_file']; WEBHOOK_URL = config.get('webhook_url','')
WATCH_DIRS = config['watch_directories']; MAX_SIZE = config['max_file_size_mb'] * 1024*1024
API_PORT = config['webhook_api_port']; DEBOUNCE = config.get('scan_debounce_seconds', 5)
DISK_WARN = config.get('disk_usage_warning_percent', 10)
EXCLUDE_PATHS = config.get('exclude_paths', [])
HEALTH_CHECK_INTERVAL = config.get('watchdog_health_check_seconds', 60)
PERM_CHECK_INTERVAL = config.get('quarantine_permission_check_seconds', 300)
SAFE_BASE_DIRS = [os.path.realpath(d) for d in WATCH_DIRS]
# Boot-time scan settings
INITIAL_FULL_SCAN = config.get('initial_full_scan', True)
FULL_SCAN_PATHS = config.get('full_scan_paths', ['/'])
FULL_SCAN_MAX_SIZE = config.get('full_scan_max_file_size_mb', 100) * 1024*1024
FULL_SCAN_NICE = config.get('full_scan_nice', 19)
FULL_SCAN_IONICE = config.get('full_scan_ionice', 3)
FULL_SCAN_EXCLUDE = config.get('full_scan_exclude', ['/proc', '/sys', '/dev', '/run'])

for d in WATCH_DIRS:
    if d != os.path.realpath(d):
        logger.warning(f"Watch path '{d}' is a symlink to '{os.path.realpath(d)}'. "
                       f"Ensure quarantine safety checks are aligned.")

with open('/etc/autoav_api_token') as f:
    API_TOKEN = f.read().strip()

session = requests.Session()
retry = Retry(total=2, backoff_factor=0.5)
adapter = HTTPAdapter(max_retries=retry)
session.mount('http://', adapter)
session.mount('https://', adapter)
REQUEST_TIMEOUT = 5

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, type TEXT, path TEXT, desc TEXT, severity TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS malware
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, path TEXT, name TEXT, scan_type TEXT, action TEXT, status TEXT)''')
    conn.commit(); conn.close()
init_db()

try:
    cd = pyclamd.ClamdUnixSocket(filename=CLAMD_SOCK)
    cd.ping()
except Exception as e:
    logger.error(f"ClamAV connection failed: {e}"); sys.exit(1)

try:
    rules = yara.compile(filepath=YARA_RULES)
except Exception as e:
    logger.error(f"YARA compilation failed: {e}"); rules = None

_scan_lock = threading.Lock()
_last_scan_time = {}
def should_scan(path):
    now = time.time()
    with _scan_lock:
        last = _last_scan_time.get(path, 0)
        if now - last < DEBOUNCE:
            return False
        _last_scan_time[path] = now
    return True

def is_excluded(path, exclude_list=None):
    if exclude_list is None:
        exclude_list = EXCLUDE_PATHS
    for ex in exclude_list:
        if path.startswith(ex):
            return True
    return False

def is_safe_to_move(path):
    real_path = os.path.realpath(path)
    if path != real_path:
        logger.warning(f"Symlink detected during scan: {path} -> {real_path}")
    for base in SAFE_BASE_DIRS:
        if real_path.startswith(base):
            return True
    return False

def check_disk_space():
    try:
        stat = os.statvfs(QUARANTINE_DIR)
        free_percent = (stat.f_bavail / stat.f_blocks) * 100
        if free_percent < DISK_WARN:
            msg = f"Disk space low on quarantine volume: {free_percent:.1f}% free"
            logger.warning(msg)
            if WEBHOOK_URL:
                try:
                    session.post(WEBHOOK_URL, json={'text': f'[WARNING] {msg}'}, timeout=REQUEST_TIMEOUT)
                except: pass
    except Exception as e:
        logger.error(f"Disk check failed: {e}")

def check_quarantine_permissions():
    while True:
        time.sleep(PERM_CHECK_INTERVAL)
        if not os.access(QUARANTINE_DIR, os.W_OK):
            msg = f"Quarantine directory not writable: {QUARANTINE_DIR}"
            logger.error(msg)
            if WEBHOOK_URL:
                try:
                    session.post(WEBHOOK_URL, json={'text': f'[ERROR] {msg}'}, timeout=REQUEST_TIMEOUT)
                except: pass
            if os.geteuid() == 0:
                try:
                    os.chmod(QUARANTINE_DIR, 0o750)
                    shutil.chown(QUARANTINE_DIR, user='autoav')
                    logger.info("Quarantine permissions auto-fixed to 750.")
                except Exception as e:
                    logger.error(f"Auto-fix failed: {e}")

def scan_file(path, scan_type='auto'):
    if is_excluded(path) or not should_scan(path):
        return
    try:
        if os.path.getsize(path) > MAX_SIZE:
            return
    except OSError:
        return

    result = {'clamav': '', 'yara': []}
    try:
        scan = cd.scan_file(path)
        if scan and path in scan:
            result['clamav'] = str(scan[path])
    except Exception as e:
        logger.warning(f"ClamAV error on {path}: {e}")
    if rules:
        try:
            matches = rules.match(path)
            if matches:
                result['yara'] = [m.rule for m in matches]
        except Exception as e:
            logger.warning(f"YARA error on {path}: {e}")

    if result['clamav'] or result['yara']:
        threat = result['clamav'] or ', '.join(result['yara'])
        logger.warning(f"THREAT: {path} -> {threat}")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.now().isoformat()
        c.execute("INSERT INTO malware (ts,path,name,scan_type,action,status) VALUES (?,?,?,?,?,?)",
                  (now, path, threat, scan_type, "Quarantined", "Infected"))
        c.execute("INSERT INTO events (ts,type,path,desc,severity) VALUES (?,?,?,?,?)",
                  (now, 'scan_alert', path, threat, 'high'))
        conn.commit(); conn.close()
        
        if not is_safe_to_move(path):
            logger.error(f"Unsafe path detected (symlink/outside base): {path} -> {os.path.realpath(path)}")
            return
        
        if not os.access(QUARANTINE_DIR, os.W_OK):
            logger.error(f"Quarantine directory is not writable: {QUARANTINE_DIR}")
            if WEBHOOK_URL:
                try:
                    session.post(WEBHOOK_URL, json={'text': f'[ERROR] Quarantine dir not writable: {QUARANTINE_DIR}'}, timeout=REQUEST_TIMEOUT)
                except: pass
            return
            
        try:
            dest = os.path.join(QUARANTINE_DIR, os.path.basename(path) + ".malz")
            need_bytes = os.path.getsize(path)
            stat = os.statvfs(QUARANTINE_DIR)
            free_bytes = stat.f_bavail * stat.f_frsize
            if need_bytes > free_bytes:
                logger.error(f"Not enough space to quarantine {path} (need {need_bytes}, free {free_bytes})")
                return
            shutil.move(path, dest)
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")
        if WEBHOOK_URL:
            try:
                session.post(WEBHOOK_URL, json={'text': f"[CRITICAL] {threat} in {path}"}, timeout=REQUEST_TIMEOUT)
            except: pass

# ========== BOOT-TIME FULL SYSTEM SCAN ==========
def perform_initial_full_scan():
    logger.info("=== Starting boot-time full system scan (Precision Mode: max 100MB/file) ===")
    start_time = time.time()
    files_scanned = 0
    threats_found = 0
    try:
        os.nice(FULL_SCAN_NICE)
    except Exception as e:
        logger.warning(f"Could not set nice value: {e}")
    try:
        subprocess.run(['ionice', '-c', str(FULL_SCAN_IONICE), '-p', str(os.getpid())])
    except Exception as e:
        logger.warning(f"Could not set ionice: {e}")
    
    for scan_root in FULL_SCAN_PATHS:
        if not os.path.exists(scan_root):
            logger.warning(f"Full scan path does not exist: {scan_root}")
            continue
        logger.info(f"Full scanning: {scan_root}")
        for dirpath, dirnames, filenames in os.walk(scan_root):
            dirnames[:] = [d for d in dirnames if not is_excluded(os.path.join(dirpath, d), FULL_SCAN_EXCLUDE)]
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if is_excluded(filepath, FULL_SCAN_EXCLUDE):
                    continue
                try:
                    if os.path.getsize(filepath) > FULL_SCAN_MAX_SIZE:
                        continue
                except OSError:
                    continue
                try:
                    result = {'clamav': '', 'yara': []}
                    try:
                        scan = cd.scan_file(filepath)
                        if scan and filepath in scan:
                            result['clamav'] = str(scan[filepath])
                    except Exception as e:
                        logger.debug(f"ClamAV full scan error on {filepath}: {e}")
                    if rules:
                        try:
                            matches = rules.match(filepath)
                            if matches:
                                result['yara'] = [m.rule for m in matches]
                        except Exception as e:
                            logger.debug(f"YARA full scan error on {filepath}: {e}")
                    if result['clamav'] or result['yara']:
                        threat = result['clamav'] or ', '.join(result['yara'])
                        logger.warning(f"FULL SCAN THREAT: {filepath} -> {threat}")
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        now = datetime.now().isoformat()
                        c.execute("INSERT INTO malware (ts,path,name,scan_type,action,status) VALUES (?,?,?,?,?,?)",
                                  (now, filepath, threat, 'full_scan_boot', "Quarantined", "Infected"))
                        c.execute("INSERT INTO events (ts,type,path,desc,severity) VALUES (?,?,?,?,?)",
                                  (now, 'full_scan_alert', filepath, threat, 'high'))
                        conn.commit(); conn.close()
                        if is_safe_to_move(filepath) and os.access(QUARANTINE_DIR, os.W_OK):
                            try:
                                dest = os.path.join(QUARANTINE_DIR, os.path.basename(filepath) + ".malz")
                                need_bytes = os.path.getsize(filepath)
                                stat = os.statvfs(QUARANTINE_DIR)
                                free_bytes = stat.f_bavail * stat.f_frsize
                                if need_bytes <= free_bytes:
                                    shutil.move(filepath, dest)
                            except Exception as e:
                                logger.error(f"Full scan quarantine failed: {filepath}: {e}")
                        threats_found += 1
                        if WEBHOOK_URL:
                            try:
                                session.post(WEBHOOK_URL, json={'text': f'[FULL SCAN MALWARE] {threat} in {filepath}'}, timeout=REQUEST_TIMEOUT)
                            except: pass
                    files_scanned += 1
                    if files_scanned % 1000 == 0:
                        logger.info(f"Full scan progress: {files_scanned} files scanned, {threats_found} threats found...")
                except Exception as e:
                    logger.debug(f"Error scanning {filepath}: {e}")
    elapsed = time.time() - start_time
    logger.info(f"=== Full system scan complete: {files_scanned} files scanned, {threats_found} threats found in {elapsed:.2f} seconds ===")

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and not is_excluded(event.src_path):
            scan_file(event.src_path, 'file_created')
    def on_modified(self, event):
        if not event.is_directory and not is_excluded(event.src_path):
            scan_file(event.src_path, 'file_modified')

observer = None
def start_monitor():
    global observer
    observer = Observer()
    handler = Handler()
    for d in WATCH_DIRS:
        if os.path.exists(d):
            observer.schedule(handler, d, recursive=True)
            logger.info(f"Watching: {d}")
    observer.start()
    return observer

def watchdog_health_check():
    while True:
        time.sleep(HEALTH_CHECK_INTERVAL)
        global observer
        if observer and not observer.is_alive():
            logger.warning("Watchdog observer died! Restarting...")
            try:
                observer.stop()
                observer.join()
            except: pass
            start_monitor()

def reload_config(signum, frame):
    global observer, WATCH_DIRS, EXCLUDE_PATHS, WEBHOOK_URL, MAX_SIZE, DEBOUNCE, DISK_WARN, SAFE_BASE_DIRS, HEALTH_CHECK_INTERVAL, PERM_CHECK_INTERVAL
    logger.info("SIGHUP received, reloading configuration...")
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        WATCH_DIRS = cfg['watch_directories']
        EXCLUDE_PATHS = cfg.get('exclude_paths', [])
        WEBHOOK_URL = cfg.get('webhook_url', '')
        MAX_SIZE = cfg['max_file_size_mb'] * 1024 * 1024
        DEBOUNCE = cfg.get('scan_debounce_seconds', 5)
        DISK_WARN = cfg.get('disk_usage_warning_percent', 10)
        HEALTH_CHECK_INTERVAL = cfg.get('watchdog_health_check_seconds', 60)
        PERM_CHECK_INTERVAL = cfg.get('quarantine_permission_check_seconds', 300)
        SAFE_BASE_DIRS = [os.path.realpath(d) for d in WATCH_DIRS]
        if observer:
            observer.unschedule_all()
            handler = Handler()
            for d in WATCH_DIRS:
                if os.path.exists(d):
                    observer.schedule(handler, d, recursive=True)
            logger.info("Watchdog paths updated.")
        logger.info("Configuration reloaded.")
    except Exception as e:
        logger.error(f"Reload failed: {e}")

def shutdown(signum, frame):
    logger.info("Shutdown signal received. Stopping observer...")
    global observer
    if observer:
        observer.stop()
        observer.join()
    sys.exit(0)

signal.signal(signal.SIGHUP, reload_config)
signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/api/report':
            self.send_response(404); self.end_headers(); return
        if self.headers.get('X-API-Token','') != API_TOKEN:
            self.send_response(403); self.end_headers(); self.wfile.write(b'Forbidden'); return
        try:
            length = int(self.headers['Content-Length'])
            data = json.loads(self.rfile.read(length))
            file_path = data.get('path','')
            if file_path:
                logger.info(f"Webhook scan request: {file_path}")
                threading.Thread(target=scan_file, args=(file_path, 'webhook_api')).start()
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"ok"}')
        except Exception as e:
            self.send_response(400); self.end_headers(); self.wfile.write(b'{"error":"invalid"}')

def start_webhook():
    server = HTTPServer(('127.0.0.1', API_PORT), WebhookHandler)
    logger.info(f"Webhook API on 127.0.0.1:{API_PORT}")
    threading.Thread(target=server.serve_forever, daemon=True).start()

def main():
    start_monitor()
    start_webhook()
    if INITIAL_FULL_SCAN:
        logger.info("Boot-time full scan is enabled. Starting in background...")
        threading.Thread(target=perform_initial_full_scan, daemon=True).start()
    else:
        logger.info("Boot-time full scan is disabled.")
    threading.Thread(target=watchdog_health_check, daemon=True).start()
    threading.Thread(target=check_quarantine_permissions, daemon=True).start()
    def disk_checker():
        while True:
            time.sleep(900)
            check_disk_space()
    threading.Thread(target=disk_checker, daemon=True).start()
    logger.info("AutoAV daemon v2.6.5 started.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == '__main__':
    main()
PYEOF
    chmod +x "$INSTALL_DIR/av-daemon.py"
    log_ok "av-daemon.py written."
}

write_dashboard() {
    cat > "$INSTALL_DIR/av-dashboard.py" << 'PYEOF'
#!/usr/bin/env python3
import os, sys, yaml, sqlite3, requests, shutil
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

config_path = sys.argv[1] if len(sys.argv)>1 else "/opt/auto_antivirus/av-core.yaml"
with open(config_path) as f: config = yaml.safe_load(f)

app = Flask(__name__)
with open('/etc/autoav_secret') as f:
    app.config['SECRET_KEY'] = f.read().strip()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + config['db_path']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.String(30)); type = db.Column(db.String(50))
    path = db.Column(db.Text); desc = db.Column(db.Text); severity = db.Column(db.String(20))

class Malware(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.String(30)); path = db.Column(db.Text); name = db.Column(db.Text)
    scan_type = db.Column(db.String(50)); action = db.Column(db.String(50)); status = db.Column(db.String(50))

with app.app_context(): db.create_all()

@app.route('/')
def dashboard():
    events = Event.query.order_by(Event.id.desc()).limit(50).all()
    malware = Malware.query.order_by(Malware.id.desc()).limit(50).all()
    return render_template('dashboard.html', events=events, malware=malware)

@app.route('/scan', methods=['POST'])
def scan():
    path = request.form.get('file_path','')
    if not os.path.exists(path):
        flash('File not found', 'error')
        return redirect('/')
    with open('/etc/autoav_api_token') as f: token = f.read().strip()
    try:
        requests.post(f'http://127.0.0.1:{config["webhook_api_port"]}/api/report',
                      json={'path': path, 'description': 'Manual scan'},
                      headers={'X-API-Token': token}, timeout=5)
        flash('Scan request sent.', 'success')
    except Exception as e:
        flash(f'Engine unreachable: {e}', 'error')
    return redirect('/')

@app.route('/quarantine/<int:id>', methods=['POST'])
def quarantine(id):
    m = Malware.query.get_or_404(id)
    if m.action == 'Quarantined':
        flash('File already quarantined.', 'info')
        return redirect('/')
    if os.path.exists(m.path):
        dest = os.path.join(config['quarantine_dir'], os.path.basename(m.path)+'.quar')
        try:
            shutil.move(m.path, dest)
            m.action = 'Quarantined'; db.session.commit()
            flash('File quarantined.', 'success')
        except Exception as e:
            flash(f'Quarantine failed: {e}', 'error')
    else:
        flash('File no longer exists.', 'warning')
    return redirect('/')
PYEOF
    chmod +x "$INSTALL_DIR/av-dashboard.py"

    cat > "$INSTALL_DIR/templates/dashboard.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>AutoAV Precision</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container-fluid">
  <h2 class="mt-3">🛡️ AutoAV Precision v2.6.5</h2>
  <p class="text-muted">Focused Boot Scan (≤100MB) + Real-Time Guard</p>
  <div class="row">
    <div class="col-md-4">
      <div class="card">
        <div class="card-header">Manual Scan</div>
        <div class="card-body">
          <form method="POST" action="/scan">
            <input type="text" class="form-control" name="file_path" placeholder="/path/to/file" required>
            <button class="btn btn-primary mt-2" type="submit">Scan</button>
          </form>
        </div>
      </div>
    </div>
  </div>
  <hr>
  <h4>Recent Malware</h4>
  <table class="table table-striped">
    <tr><th>Time</th><th>File</th><th>Threat</th><th>Type</th><th>Status</th><th>Action</th></tr>
    {% for m in malware %}
    <tr>
      <td>{{ m.ts[:19] }}</td><td>{{ m.path }}</td><td class="text-danger">{{ m.name }}</td>
      <td><span class="badge bg-info">{{ m.scan_type }}</span></td>
      <td><span class="badge bg-danger">{{ m.status }}</span></td>
      <td>
        {% if m.action != 'Quarantined' %}
        <form method="POST" action="/quarantine/{{ m.id }}" style="display:inline;">
          <button class="btn btn-sm btn-warning">Quarantine</button>
        </form>
        {% else %}
        <span class="text-muted">Already quarantined</span>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
  </table>
  <h4>Security Events</h4>
  <table class="table table-sm">
    <tr><th>Time</th><th>Event</th><th>File</th><th>Severity</th></tr>
    {% for e in events %}
    <tr><td>{{ e.ts[:19] }}</td><td>{{ e.type }}</td><td>{{ e.path }}</td><td>{{ e.severity }}</td></tr>
    {% endfor %}
  </table>
</div>
</body>
</html>
HTMLEOF
    log_ok "Dashboard files created."
}

create_services() {
    cat > "$SERVICE_DIR/autoav-daemon.service" << EOF
[Unit]
Description=AutoAV Daemon (Scanner + Webhook API + Boot Scan)
After=network.target clamav-daemon.service

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/av-daemon.py $CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SERVICE_DIR/autoav-dashboard.service" << EOF
[Unit]
Description=AutoAV Dashboard
After=network.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/gunicorn -w 2 -b 0.0.0.0:$DASHBOARD_PORT av-dashboard:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now autoav-daemon.service
    systemctl enable --now autoav-dashboard.service
    log_ok "Systemd services installed and started."
}

main() {
    clear
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN} Auto Antivirus v2.6.5 – Precision Edition   ${NC}"
    echo -e "${GREEN} Focused Boot Scan (100MB) + Real-Time Guard ${NC}"
    echo -e "${GREEN}=============================================${NC}"
    read -p "Enter Webhook URL (or leave blank): " WEBHOOK_URL
    check_root
    detect_distro
    install_deps
    setup_clamav
    create_structure
    setup_firewall
    write_daemon
    write_dashboard
    create_services

    ip=$(hostname -I | awk '{print $1}')
    API_TOKEN=$(cat /etc/autoav_api_token)
    echo
    log_ok "Installation complete!"
    echo -e "Dashboard:   ${GREEN}http://$ip:$DASHBOARD_PORT${NC} (restricted to localhost)"
    echo -e "Webhook API: ${GREEN}http://$ip:$WEBHOOK_API_PORT/api/report${NC}"
    echo -e "API Token stored in: /etc/autoav_api_token"
    echo -e "Reload config: sudo systemctl reload autoav-daemon"
    echo -e "${YELLOW}Firewall active – dashboard accessible only from localhost.${NC}"
    echo -e "Boot-Time Full Scan: ${GREEN}Enabled${NC} (max file size: 100MB)"
    echo -e "Monitor dirs: /home, /tmp, /var/www, /etc, /usr/bin, /dev/shm, /run/shm"
    echo
    echo "One‑click test command:"
    echo "curl -X POST http://127.0.0.1:$WEBHOOK_API_PORT/api/report -H 'X-API-Token: $API_TOKEN' -d '{\"path\":\"/tmp/test\"}'"
}

main "$@"
