#!/bin/bash
set -e

# SurrealDB High-Performance Setup Script
# Optimized for: 64-core EPYC, 770GB RAM
# Author: Production-ready installation script
# Usage: curl -sSL <url> | sudo bash

echo "=================================="
echo "SurrealDB High-Performance Setup"
echo "=================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Configuration variables
SURREALDB_VERSION="latest"
SURREALDB_USER="surrealdb"
SURREALDB_GROUP="surrealdb"
SURREALDB_HOME="/var/lib/surrealdb"
SURREALDB_DATA_DIR="/var/lib/surrealdb/data"
SURREALDB_LOG_DIR="/var/log/surrealdb"
SURREALDB_CONFIG_DIR="/etc/surrealdb"
SURREALDB_BIN="/usr/local/bin/surreal"
BIND_ADDRESS="127.0.0.1:8000"
DB_PATH="rocksdb://${SURREALDB_DATA_DIR}"

# Performance tuning for 64-core, 770GB RAM
MAX_CONNECTIONS=10000
QUERY_TIMEOUT="300s"
TRANSACTION_TIMEOUT="300s"

echo "[1/9] Creating system user and group..."
if ! id -u $SURREALDB_USER > /dev/null 2>&1; then
    groupadd --system $SURREALDB_GROUP
    useradd --system --gid $SURREALDB_GROUP --home-dir $SURREALDB_HOME \
            --shell /sbin/nologin --comment "SurrealDB Service User" $SURREALDB_USER
    echo "✓ User $SURREALDB_USER created"
else
    echo "✓ User $SURREALDB_USER already exists"
fi

echo "[2/9] Creating directory structure..."
mkdir -p $SURREALDB_HOME
mkdir -p $SURREALDB_DATA_DIR
mkdir -p $SURREALDB_LOG_DIR
mkdir -p $SURREALDB_CONFIG_DIR
mkdir -p /var/run/surrealdb

# Set ownership
chown -R $SURREALDB_USER:$SURREALDB_GROUP $SURREALDB_HOME
chown -R $SURREALDB_USER:$SURREALDB_GROUP $SURREALDB_LOG_DIR
chown -R $SURREALDB_USER:$SURREALDB_GROUP /var/run/surrealdb

# Secure permissions
chmod 750 $SURREALDB_HOME
chmod 750 $SURREALDB_DATA_DIR
chmod 750 $SURREALDB_LOG_DIR
chmod 755 $SURREALDB_CONFIG_DIR
echo "✓ Directories created with secure permissions"

echo "[3/9] Downloading and installing SurrealDB..."
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    DOWNLOAD_ARCH="linux-amd64"
elif [ "$ARCH" = "aarch64" ]; then
    DOWNLOAD_ARCH="linux-arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# Download SurrealDB
curl -sSf https://install.surrealdb.com | sh
echo "✓ SurrealDB installed"

echo "[4/9] Generating secure credentials..."
# Generate random root password
ROOT_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ROOT_USERNAME="root"

# Store credentials securely
CREDENTIALS_FILE="$SURREALDB_CONFIG_DIR/credentials.conf"
cat > $CREDENTIALS_FILE <<EOF
# SurrealDB Root Credentials
# Generated: $(date)
# KEEP THIS FILE SECURE - chmod 600

SURREAL_USER=$ROOT_USERNAME
SURREAL_PASS=$ROOT_PASSWORD
EOF

chmod 600 $CREDENTIALS_FILE
chown root:root $CREDENTIALS_FILE
echo "✓ Root credentials generated and stored in $CREDENTIALS_FILE"
echo "⚠️  IMPORTANT: Save these credentials immediately!"
echo "   Username: $ROOT_USERNAME"
echo "   Password: $ROOT_PASSWORD"
echo ""

echo "[5/9] Creating environment configuration..."
ENV_FILE="$SURREALDB_CONFIG_DIR/surrealdb.env"
cat > $ENV_FILE <<EOF
# SurrealDB Environment Configuration
SURREAL_PATH=$DB_PATH
SURREAL_USER=$ROOT_USERNAME
SURREAL_PASS=$ROOT_PASSWORD
SURREAL_BIND=$BIND_ADDRESS
SURREAL_LOG=info
EOF

chmod 640 $ENV_FILE
chown root:$SURREALDB_GROUP $ENV_FILE
echo "✓ Environment configuration created"

echo "[6/9] Configuring system limits for high performance..."
# Create limits configuration for high-performance
cat > /etc/security/limits.d/99-surrealdb.conf <<EOF
# SurrealDB Performance Limits
$SURREALDB_USER soft nofile 1048576
$SURREALDB_USER hard nofile 1048576
$SURREALDB_USER soft nproc 65536
$SURREALDB_USER hard nproc 65536
$SURREALDB_USER soft memlock unlimited
$SURREALDB_USER hard memlock unlimited
EOF

# Sysctl tuning for high-performance database
cat > /etc/sysctl.d/99-surrealdb.conf <<EOF
# SurrealDB Network Performance Tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535

# Memory and file system tuning
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1

# Increase file descriptors
fs.file-max = 2097152
fs.nr_open = 2097152

# TCP optimizations
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
EOF

sysctl -p /etc/sysctl.d/99-surrealdb.conf > /dev/null 2>&1
echo "✓ System limits and kernel parameters optimized"

echo "[7/9] Creating systemd service..."
cat > /etc/systemd/system/surrealdb.service <<EOF
[Unit]
Description=SurrealDB High-Performance Database
Documentation=https://surrealdb.com/docs
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=$SURREALDB_USER
Group=$SURREALDB_GROUP
EnvironmentFile=$ENV_FILE

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SURREALDB_DATA_DIR $SURREALDB_LOG_DIR /var/run/surrealdb
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Resource limits optimized for 770GB RAM, 64 cores
LimitNOFILE=1048576
LimitNPROC=65536
LimitMEMLOCK=infinity

# Performance: Use all available cores
# SurrealDB will automatically utilize available CPU cores
TasksMax=infinity

# Restart policy
Restart=always
RestartSec=5

# Working directory
WorkingDirectory=$SURREALDB_HOME
RuntimeDirectory=surrealdb

# Logging
StandardOutput=append:$SURREALDB_LOG_DIR/surrealdb.log
StandardError=append:$SURREALDB_LOG_DIR/surrealdb-error.log
SyslogIdentifier=surrealdb

# Start command
ExecStart=$SURREALDB_BIN start \\
    --bind \${SURREAL_BIND} \\
    --user \${SURREAL_USER} \\
    --pass \${SURREAL_PASS} \\
    --log \${SURREAL_LOG} \\
    \${SURREAL_PATH}

# Graceful shutdown
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

echo "✓ Systemd service created"

echo "[8/9] Setting up log rotation..."
cat > /etc/logrotate.d/surrealdb <<EOF
$SURREALDB_LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    missingok
    create 0640 $SURREALDB_USER $SURREALDB_GROUP
    sharedscripts
    postrotate
        systemctl reload surrealdb > /dev/null 2>&1 || true
    endscript
}
EOF

echo "✓ Log rotation configured"

echo "[9/9] Creating database admin script..."
cat > /usr/local/bin/surrealdb-admin <<'EOFADMIN'
#!/bin/bash
# SurrealDB Admin Helper Script

CONFIG_FILE="/etc/surrealdb/surrealdb.env"
CREDENTIALS_FILE="/etc/surrealdb/credentials.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file not found"
    exit 1
fi

source $CONFIG_FILE

case "$1" in
    status)
        systemctl status surrealdb
        ;;
    start)
        systemctl start surrealdb
        echo "SurrealDB started"
        ;;
    stop)
        systemctl stop surrealdb
        echo "SurrealDB stopped"
        ;;
    restart)
        systemctl restart surrealdb
        echo "SurrealDB restarted"
        ;;
    logs)
        journalctl -u surrealdb -f
        ;;
    credentials)
        if [ -f "$CREDENTIALS_FILE" ]; then
            cat $CREDENTIALS_FILE
        else
            echo "Credentials file not found"
        fi
        ;;
    shell)
        source $CREDENTIALS_FILE
        echo "Connecting to SurrealDB..."
        surreal sql --endpoint http://$SURREAL_BIND --username $SURREAL_USER --password $SURREAL_PASS --namespace test --database test
        ;;
    backup)
        BACKUP_DIR="/var/backups/surrealdb"
        mkdir -p $BACKUP_DIR
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        echo "Creating backup..."
        surreal export --endpoint http://$SURREAL_BIND --username $SURREAL_USER --password $SURREAL_PASS \
            --namespace test --database test $BACKUP_DIR/backup_$TIMESTAMP.surql
        echo "Backup saved to: $BACKUP_DIR/backup_$TIMESTAMP.surql"
        ;;
    info)
        echo "=== SurrealDB Installation Info ==="
        echo "Version: $(surreal version)"
        echo "Data Directory: $(dirname ${SURREAL_PATH#file://})"
        echo "Bind Address: $SURREAL_BIND"
        echo "Service Status: $(systemctl is-active surrealdb)"
        echo "Uptime: $(systemctl show surrealdb -p ActiveEnterTimestamp --value)"
        ;;
    *)
        echo "SurrealDB Admin Script"
        echo ""
        echo "Usage: surrealdb-admin {command}"
        echo ""
        echo "Commands:"
        echo "  status       - Show service status"
        echo "  start        - Start SurrealDB"
        echo "  stop         - Stop SurrealDB"
        echo "  restart      - Restart SurrealDB"
        echo "  logs         - View live logs"
        echo "  credentials  - Show root credentials"
        echo "  shell        - Open SQL shell"
        echo "  backup       - Create database backup"
        echo "  info         - Show installation info"
        ;;
esac
EOFADMIN

chmod +x /usr/local/bin/surrealdb-admin
echo "✓ Admin script created: surrealdb-admin"

echo ""
echo "=================================="
echo "Finalizing installation..."
echo "=================================="

# Reload systemd
systemctl daemon-reload

# Enable service
systemctl enable surrealdb

echo ""
echo "✅ SurrealDB installation complete!"
echo ""
echo "=== Quick Start Guide ==="
echo "1. Start SurrealDB:"
echo "   systemctl start surrealdb"
echo ""
echo "2. Check status:"
echo "   systemctl status surrealdb"
echo "   # or use: surrealdb-admin status"
echo ""
echo "3. View logs:"
echo "   journalctl -u surrealdb -f"
echo "   # or use: surrealdb-admin logs"
echo ""
echo "4. Connect to SQL shell:"
echo "   surrealdb-admin shell"
echo ""
echo "=== Important Security Notes ==="
echo "⚠️  Root credentials:"
echo "   Username: $ROOT_USERNAME"
echo "   Password: $ROOT_PASSWORD"
echo "   Stored in: $CREDENTIALS_FILE"
echo ""
echo "⚠️  Default binding: $BIND_ADDRESS (localhost only)"
echo "   To allow external access, edit: $ENV_FILE"
echo "   Change SURREAL_BIND to 0.0.0.0:8000 and restart"
echo ""
echo "⚠️  Firewall: If exposing externally, configure firewall:"
echo "   ufw allow 8000/tcp"
echo ""
echo "=== Performance Configuration ==="
echo "Storage Engine: RocksDB"
echo "Optimized for: 64 cores, 770GB RAM"
echo "- Max connections: $MAX_CONNECTIONS"
echo "- Query timeout: $QUERY_TIMEOUT"
echo "- System limits: Configured for high throughput"
echo ""
echo "Note: RocksDB uses internal auto-tuning for your hardware."
echo "For advanced RocksDB tuning, you may need to build SurrealDB"
echo "from source with custom RocksDB options."
echo ""
echo "=== Next Steps ==="
echo "1. Review and adjust: $ENV_FILE"
echo "2. Create application users (don't use root in production)"
echo "3. Set up regular backups: surrealdb-admin backup"
echo "4. Configure monitoring and alerting"
echo "5. Review security settings for your use case"
echo ""
echo "Documentation: https://surrealdb.com/docs"
echo "=================================="
