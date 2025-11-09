#!/bin/bash
#
# Apache Druid Secure Installation Script
# Auto-detects latest version, configures security, creates systemd services
# NOW WITH: Cleanup of old installations and user recreation
#
# Usage: 
#   curl -fsSL https://nik.technology/setup_druid.sh | sudo bash
#

set -e
set -o pipefail

# ============================================
# Configuration Variables
# ============================================
INSTALL_DIR="/opt"
DRUID_USER="druid"
DRUID_GROUP="druid"
DATA_DIR="/var/druid"
LOG_DIR="/var/log/druid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================
# Helper Functions
# ============================================
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Read from terminal even when piped
read_from_tty() {
    local prompt="$1"
    local response
    
    if [ -t 0 ]; then
        read -p "$prompt" response
    else
        if [ -e /dev/tty ]; then
            read -p "$prompt" response < /dev/tty
        else
            error "Cannot read input in non-interactive mode"
            exit 1
        fi
    fi
    
    echo "$response"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        error "Cannot detect OS"
        exit 1
    fi
    log "Detected OS: $OS $OS_VERSION"
}

# Generate secure random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Read password securely with confirmation
read_password() {
    local prompt=$1
    local password=""
    local password_confirm=""
    
    while true; do
        if [ -t 0 ]; then
            read -s -p "$prompt (min 12 chars, or press Enter to auto-generate): " password
            echo
        else
            if [ -e /dev/tty ]; then
                read -s -p "$prompt (min 12 chars, or press Enter to auto-generate): " password < /dev/tty
                echo
            else
                error "Cannot read password in non-interactive mode"
                exit 1
            fi
        fi
        
        # If empty, auto-generate password
        if [ -z "$password" ]; then
            password=$(generate_password)
            info "Auto-generated password: $password"
            info "SAVE THIS PASSWORD - it will only be shown once!"
            echo "$password"
            return
        fi
        
        # Validate length for manually entered passwords
        if [ ${#password} -lt 12 ]; then
            error "Password must be at least 12 characters long"
            continue
        fi
        
        # Confirm manually entered password
        if [ -t 0 ]; then
            read -s -p "Confirm password: " password_confirm
            echo
        else
            if [ -e /dev/tty ]; then
                read -s -p "Confirm password: " password_confirm < /dev/tty
                echo
            else
                error "Cannot read password in non-interactive mode"
                exit 1
            fi
        fi
        
        if [ "$password" = "$password_confirm" ]; then
            echo "$password"
            return
        else
            error "Passwords do not match. Please try again."
        fi
    done
}

# Hash password using OpenSSL (SHA-512)
hash_password() {
    local password="$1"
    # Using SHA-512 (same as Linux /etc/shadow)
    openssl passwd -6 "$password"
}

# ============================================
# Cleanup Old Installation
# ============================================
cleanup_old_installation() {
    log "Checking for existing Druid installation..."
    
    local found_old=0
    
    # Check for existing Druid directories
    if [ -d "$INSTALL_DIR/druid" ] || [ -L "$INSTALL_DIR/druid" ]; then
        found_old=1
        warning "Found existing Druid installation at $INSTALL_DIR/druid"
    fi
    
    if ls "$INSTALL_DIR"/apache-druid-* 1> /dev/null 2>&1; then
        found_old=1
        warning "Found existing Druid version directories"
    fi
    
    if systemctl list-unit-files 2>/dev/null | grep -q "druid.service"; then
        found_old=1
        warning "Found existing Druid systemd service"
    fi
    
    if id "$DRUID_USER" &>/dev/null; then
        found_old=1
        warning "Found existing Druid user: $DRUID_USER"
    fi
    
    if [ $found_old -eq 0 ]; then
        log "No existing installation found, proceeding with fresh install"
        return 0
    fi
    
    echo ""
    warning "═══════════════════════════════════════════════════════════════"
    warning "  EXISTING DRUID INSTALLATION DETECTED"
    warning "═══════════════════════════════════════════════════════════════"
    echo ""
    info "The following will be cleaned up:"
    echo "  • Stop and remove Druid systemd services"
    echo "  • Remove old Druid installation directories"
    echo "  • Remove and recreate Druid system user"
    echo "  • Backup existing configuration to /etc/druid/backup-<timestamp>"
    echo ""
    warning "  ⚠️  DATA DIRECTORY ($DATA_DIR) WILL BE PRESERVED"
    warning "  ⚠️  To start fresh, manually delete it after this script"
    echo ""
    
    CLEANUP=$(read_from_tty "Clean up old installation? (y/n): ")
    if [[ ! "$CLEANUP" =~ ^[Yy]$ ]]; then
        error "Cannot proceed with existing installation. Exiting."
        exit 1
    fi
    
    echo ""
    log "Starting cleanup process..."
    
    # Stop Druid service if running
    if systemctl is-active --quiet druid.service 2>/dev/null; then
        log "Stopping Druid service..."
        systemctl stop druid.service || warning "Failed to stop druid.service"
        sleep 3
    fi
    
    # Disable and remove systemd service
    if systemctl is-enabled --quiet druid.service 2>/dev/null; then
        log "Disabling Druid service..."
        systemctl disable druid.service || warning "Failed to disable druid.service"
    fi
    
    if [ -f /etc/systemd/system/druid.service ]; then
        log "Removing systemd service file..."
        rm -f /etc/systemd/system/druid.service
        systemctl daemon-reload
    fi
    
    # Backup existing configuration
    if [ -d /etc/druid ]; then
        BACKUP_DIR="/etc/druid/backup-$(date +%Y%m%d-%H%M%S)"
        log "Backing up existing configuration to $BACKUP_DIR..."
        mkdir -p "$BACKUP_DIR"
        cp -r /etc/druid/* "$BACKUP_DIR/" 2>/dev/null || true
        chmod -R 600 "$BACKUP_DIR"
        log "Backup completed: $BACKUP_DIR"
    fi
    
    # Remove old Druid installations
    log "Removing old Druid installation directories..."
    
    if [ -L "$INSTALL_DIR/druid" ]; then
        rm -f "$INSTALL_DIR/druid"
    fi
    
    if [ -d "$INSTALL_DIR/druid" ] && [ ! -L "$INSTALL_DIR/druid" ]; then
        rm -rf "$INSTALL_DIR/druid"
    fi
    
    # Remove all apache-druid-* directories
    find "$INSTALL_DIR" -maxdepth 1 -type d -name "apache-druid-*" -exec rm -rf {} + 2>/dev/null || true
    
    # Remove downloaded packages
    find "$INSTALL_DIR" -maxdepth 1 -type f -name "apache-druid-*.tar.gz*" -exec rm -f {} + 2>/dev/null || true
    
    # Remove and recreate user
    if id "$DRUID_USER" &>/dev/null; then
        log "Removing existing Druid user and group..."
        
        # Kill any processes owned by the user
        pkill -u "$DRUID_USER" 2>/dev/null || true
        sleep 2
        
        # Force kill if still running
        pkill -9 -u "$DRUID_USER" 2>/dev/null || true
        sleep 1
        
        # Remove user (with home directory if possible)
        userdel -r "$DRUID_USER" 2>/dev/null || userdel "$DRUID_USER" 2>/dev/null || true
        
        # Remove group if it still exists
        groupdel "$DRUID_GROUP" 2>/dev/null || true
        
        log "Druid user and group removed"
    fi
    
    # Clean up /etc/druid (except backup directory)
    if [ -d /etc/druid ]; then
        log "Cleaning /etc/druid (preserving backups)..."
        find /etc/druid -mindepth 1 -maxdepth 1 ! -name 'backup*' -exec rm -rf {} + 2>/dev/null || true
    fi
    
    # Clean up log directory old files (preserve directory structure)
    if [ -d "$LOG_DIR" ]; then
        log "Cleaning old log files..."
        find "$LOG_DIR" -type f -name "*.log*" -exec rm -f {} + 2>/dev/null || true
    fi
    
    log "Cleanup completed successfully"
    echo ""
}

# ============================================
# Install Dependencies
# ============================================
install_dependencies() {
    log "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y \
                openjdk-17-jdk \
                wget \
                curl \
                python3 \
                perl \
                tar \
                gzip \
                net-tools \
                gnupg \
                ca-certificates \
                openssl \
                jq
            ;;
        centos|rhel|rocky|almalinux)
            yum install -y \
                java-17-openjdk \
                java-17-openjdk-devel \
                wget \
                curl \
                python3 \
                perl \
                tar \
                gzip \
                net-tools \
                gnupg \
                ca-certificates \
                openssl \
                jq
            ;;
        fedora)
            dnf install -y \
                java-17-openjdk \
                java-17-openjdk-devel \
                wget \
                curl \
                python3 \
                perl \
                tar \
                gzip \
                net-tools \
                gnupg \
                ca-certificates \
                openssl \
                jq
            ;;
        *)
            error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    # Verify Java 17
    if ! java -version 2>&1 | grep -q "version \"17"; then
        error "Java 17 installation failed or wrong version detected"
        exit 1
    fi
    
    log "Dependencies installed successfully"
}

# ============================================
# Detect Latest Druid Version
# ============================================
get_latest_version() {
    log "Detecting latest Druid version from GitHub..."
    
    if command -v jq &> /dev/null; then
        DRUID_VERSION=$(curl -fsSL https://api.github.com/repos/apache/druid/releases/latest | jq -r '.tag_name' | sed 's/^druid-//')
    else
        DRUID_VERSION=$(curl -fsSL https://api.github.com/repos/apache/druid/releases/latest | grep -Po '"tag_name":\s*"druid-\K[^"]+' | head -1)
    fi
    
    if [ -z "$DRUID_VERSION" ]; then
        error "Failed to detect latest Druid version"
        exit 1
    fi
    
    log "Latest Druid version: $DRUID_VERSION"
}

# ============================================
# Create System User
# ============================================
create_user() {
    log "Creating Druid system user..."
    
    if id "$DRUID_USER" &>/dev/null; then
        error "User $DRUID_USER still exists after cleanup. This should not happen."
        exit 1
    fi
    
    useradd -r -m -U -d "$INSTALL_DIR/druid" -s /bin/bash "$DRUID_USER"
    log "Created system user: $DRUID_USER"
}

# ============================================
# Download and Verify Druid
# ============================================
download_druid() {
    log "Downloading Apache Druid $DRUID_VERSION..."
    
    cd "$INSTALL_DIR"
    DRUID_PACKAGE="apache-druid-${DRUID_VERSION}-bin.tar.gz"
    DRUID_URL="https://dlcdn.apache.org/druid/${DRUID_VERSION}/${DRUID_PACKAGE}"
    SHA512_URL="https://www.apache.org/dist/druid/${DRUID_VERSION}/${DRUID_PACKAGE}.sha512"
    
    if [ ! -f "$DRUID_PACKAGE" ]; then
        wget -q --show-progress "$DRUID_URL" || {
            error "Failed to download Druid from $DRUID_URL"
            exit 1
        }
    else
        warning "Druid package already downloaded, skipping"
    fi
    
    wget -q "$SHA512_URL" -O "${DRUID_PACKAGE}.sha512"
    
    log "Verifying checksum..."
    
    # Read the downloaded checksum file
    EXPECTED_CHECKSUM=$(cat "${DRUID_PACKAGE}.sha512" | awk '{print $1}')
    
    # Calculate actual checksum
    ACTUAL_CHECKSUM=$(sha512sum "$DRUID_PACKAGE" | awk '{print $1}')
    
    # Compare checksums
    if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
        log "Checksum verification successful"
        log "SHA512: ${ACTUAL_CHECKSUM:0:16}..."
    else
        error "Checksum verification failed!"
        error "Expected: $EXPECTED_CHECKSUM"
        error "Got:      $ACTUAL_CHECKSUM"
        exit 1
    fi
    
    log "Extracting Druid..."
    tar -xzf "$DRUID_PACKAGE"
    
    rm -rf druid
    ln -s "apache-druid-${DRUID_VERSION}" druid
    
    DRUID_HOME="$INSTALL_DIR/druid"
    log "Druid extracted to: $DRUID_HOME"
}

# ============================================
# Create Directory Structure
# ============================================
create_directories() {
    log "Creating directory structure with secure permissions..."
    
    mkdir -p "$DATA_DIR"/{segments,segment-cache,segment-cache-info,indexing-logs,task,persistent,tmp}
    mkdir -p "$LOG_DIR"
    mkdir -p /etc/druid/backup
    
    chown -R $DRUID_USER:$DRUID_GROUP "$DATA_DIR"
    chown -R $DRUID_USER:$DRUID_GROUP "$LOG_DIR"
    chown -R $DRUID_USER:$DRUID_GROUP "$DRUID_HOME"
    
    chmod 700 "$DATA_DIR"
    chmod -R 700 "$DATA_DIR"/*
    chmod 750 "$LOG_DIR"
    
    log "Directory structure created with secure permissions"
}

# ============================================
# Prompt for Credentials
# ============================================
prompt_credentials() {
    log "Setting up authentication credentials..."
    echo ""
    
    info "Configure ADMIN user credentials (full cluster access)"
    info "Note: Admin username is fixed as 'admin' (Druid requirement)"
    
    ADMIN_USER="admin"
    ADMIN_PASSWORD=$(read_password "Enter admin password")
    
    echo ""
    
    info "Generating internal system password (for inter-service communication)..."
    INTERNAL_PASSWORD=$(generate_password)
    
    echo ""
    CREATE_READONLY=$(read_from_tty "Create a read-only user? (y/n) [y]: ")
    CREATE_READONLY=${CREATE_READONLY:-y}
    
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        READONLY_USER=$(read_from_tty "Enter read-only username [analyst]: ")
        READONLY_USER=${READONLY_USER:-analyst}
        READONLY_PASSWORD=$(read_password "Enter read-only user password")
    fi
    
    echo ""
    log "Credentials configured"
}

# ============================================
# Configure Druid Security
# ============================================
configure_security() {
    log "Configuring Druid security settings..."
    
    # Create /etc/druid directory if it doesn't exist
    mkdir -p /etc/druid
    
    # Save all credentials to env file
    cat > /etc/druid/druid.env << EOF
# Druid Security Environment Variables
# Generated: $(date)
# DO NOT SHARE THIS FILE - Contains sensitive credentials

DRUID_ADMIN_USER=$ADMIN_USER
DRUID_ADMIN_PASSWORD=$ADMIN_PASSWORD
DRUID_INTERNAL_PASSWORD=$INTERNAL_PASSWORD
EOF

    # Add readonly user if configured
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        cat >> /etc/druid/druid.env << EOF
DRUID_READONLY_USER=$READONLY_USER
DRUID_READONLY_PASSWORD=$READONLY_PASSWORD
EOF
    fi
    
    chmod 600 /etc/druid/druid.env
    chown $DRUID_USER:$DRUID_GROUP /etc/druid/druid.env
    
    cp -r "$DRUID_HOME/conf" /etc/druid/backup/
    
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties" << 'EOF'
#
# Apache Druid - Secure Production Configuration
#

# Extensions (REQUIRED for security)
druid.extensions.loadList=["druid-basic-security", "druid-histogram", "druid-datasketches", "druid-kafka-indexing-service", "mysql-metadata-storage", "postgresql-metadata-storage"]

# Logging
druid.startup.logging.logProperties=true
druid.startup.logging.maskProperties=["password", "key", "secret", "token"]

# Zookeeper
druid.zk.service.host=localhost:2181
druid.zk.paths.base=/druid

# Metadata Storage (Derby for testing - USE POSTGRESQL/MYSQL IN PRODUCTION)
druid.metadata.storage.type=derby
druid.metadata.storage.connector.connectURI=jdbc:derby://localhost:1527/var/druid/metadata.db;create=true
druid.metadata.storage.connector.host=localhost
druid.metadata.storage.connector.port=1527
druid.metadata.storage.connector.createTables=true

# Deep Storage (local for testing - USE S3/HDFS/GCS IN PRODUCTION)
druid.storage.type=local
druid.storage.storageDirectory=/var/druid/segments

# Indexing Service Logs
druid.indexer.logs.type=file
druid.indexer.logs.directory=/var/log/druid/indexing-logs

# Service Discovery
druid.selectors.indexing.serviceName=druid/overlord
druid.selectors.coordinator.serviceName=druid/coordinator

# Monitoring
druid.monitoring.monitors=["org.apache.druid.java.util.metrics.JvmMonitor"]
druid.emitter=noop
druid.emitter.logging.logLevel=info

# ============================================
# SECURITY CONFIGURATION
# ============================================

# Host binding (localhost for security)
druid.host=localhost
druid.bindOnHost=true

# Authentication - Basic Auth with Metadata Store
druid.auth.authenticatorChain=["MyBasicMetadataAuthenticator"]
druid.auth.authenticator.MyBasicMetadataAuthenticator.type=basic
druid.auth.authenticator.MyBasicMetadataAuthenticator.initialAdminPassword=${env:DRUID_ADMIN_PASSWORD}
druid.auth.authenticator.MyBasicMetadataAuthenticator.initialInternalClientPassword=${env:DRUID_INTERNAL_PASSWORD}
druid.auth.authenticator.MyBasicMetadataAuthenticator.credentialsValidator.type=metadata
druid.auth.authenticator.MyBasicMetadataAuthenticator.skipOnFailure=false
druid.auth.authenticator.MyBasicMetadataAuthenticator.authorizerName=MyBasicMetadataAuthorizer

# Authorization
druid.auth.authorizers=["MyBasicMetadataAuthorizer"]
druid.auth.authorizer.MyBasicMetadataAuthorizer.type=basic

# Escalator (internal system authentication)
druid.escalator.type=basic
druid.escalator.internalClientUsername=druid_system
druid.escalator.internalClientPassword=${env:DRUID_INTERNAL_PASSWORD}
druid.escalator.authorizerName=MyBasicMetadataAuthorizer

# Security Hardening
druid.server.http.showDetailedJettyErrors=false
druid.request.logging.type=slf4j
druid.javascript.enabled=false
druid.sql.planner.authorizeSystemTablesDirectly=true

EOF
    
    chmod 600 "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    
    log "Security configuration completed"
}

# ============================================
# Configure Service-Specific Settings
# ============================================
configure_services() {
    log "Configuring individual Druid services..."
    
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/router/runtime.properties" << 'EOF'
druid.service=druid/router
druid.plaintextPort=8888
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.router.http.numConnections=50
druid.router.http.readTimeout=PT5M
druid.router.http.numMaxThreads=100
druid.server.http.numThreads=100
druid.router.managementProxy.enabled=true
druid.router.sql.enable=true
EOF

    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties" << 'EOF'
druid.service=druid/coordinator
druid.plaintextPort=8081
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.coordinator.startDelay=PT10S
druid.coordinator.period=PT30S
druid.indexer.queue.startDelay=PT5S
druid.indexer.runner.type=local
druid.indexer.storage.type=metadata
EOF

    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/broker/runtime.properties" << 'EOF'
druid.service=druid/broker
druid.plaintextPort=8082
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.processing.buffer.sizeBytes=134217728
druid.processing.numThreads=1
druid.processing.numMergeBuffers=1
druid.broker.cache.useCache=true
druid.broker.cache.populateCache=true
druid.cache.type=caffeine
druid.cache.sizeInBytes=134217728
druid.sql.enable=true
EOF

    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/historical/runtime.properties" << 'EOF'
druid.service=druid/historical
druid.plaintextPort=8083
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.processing.buffer.sizeBytes=134217728
druid.processing.numThreads=1
druid.processing.numMergeBuffers=1
druid.segmentCache.locations=[{"path":"/var/druid/segment-cache","maxSize":1073741824}]
druid.segmentCache.infoDir=/var/druid/segment-cache-info
druid.server.maxSize=1073741824
EOF

    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/middleManager/runtime.properties" << 'EOF'
druid.service=druid/middleManager
druid.plaintextPort=8091
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.indexer.runner.javaOpts=-server -Xms256m -Xmx256m -XX:MaxDirectMemorySize=256m -Duser.timezone=UTC -Dfile.encoding=UTF-8 -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager -Djava.io.tmpdir=/var/druid/tmp
druid.indexer.task.baseTaskDir=/var/druid/task
druid.indexer.task.restoreTasksOnRestart=false
druid.worker.capacity=2
druid.indexer.fork.property.druid.processing.numThreads=1
druid.indexer.fork.property.druid.processing.buffer.sizeBytes=134217728
EOF
    
    log "Service-specific configurations completed"
}

# ============================================
# Create Systemd Service Files
# ============================================
create_systemd_services() {
    log "Creating systemd service files..."
    
    cat > /etc/systemd/system/druid.service << EOF
[Unit]
Description=Apache Druid (All Services - nano-quickstart)
Documentation=https://druid.apache.org/docs/latest/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$DRUID_USER
Group=$DRUID_GROUP
EnvironmentFile=/etc/druid/druid.env
Environment="DRUID_JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64"
WorkingDirectory=$DRUID_HOME
ExecStart=$DRUID_HOME/bin/start-nano-quickstart
ExecStop=/bin/kill -SIGTERM \$MAINPID
Restart=on-failure
RestartSec=30s
TimeoutStartSec=300
TimeoutStopSec=300

# Resource Limits
LimitNOFILE=65536
LimitNPROC=32768

# Security Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR $DRUID_HOME/var
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=druid

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    log "Systemd service created: druid.service"
}

# ============================================
# Create Management Scripts
# ============================================
create_management_scripts() {
    log "Creating management scripts..."
    
    cat > "$DRUID_HOME/bin/check-status.sh" << 'EOF'
#!/bin/bash
echo "Checking Druid services health..."
echo ""

services=("coordinator:8081" "broker:8082" "historical:8083" "router:8888" "middleManager:8091")

for service_port in "${services[@]}"; do
    IFS=':' read -r service port <<< "$service_port"
    printf "%-15s " "$service:"
    
    if curl -s -f http://localhost:$port/status/health > /dev/null 2>&1; then
        echo -e "\033[0;32mHealthy\033[0m"
    else
        echo -e "\033[0;31mUnhealthy or not running\033[0m"
    fi
done

echo ""
echo "Web Console: http://localhost:8888"
echo "Use SSH tunnel for remote access: ssh -L 8888:localhost:8888 user@server"
EOF

    chmod +x "$DRUID_HOME/bin/check-status.sh"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/bin/check-status.sh"
    
    # Create user setup script (runs after Druid starts)
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        cat > "$DRUID_HOME/bin/create-users.sh" << EOF
#!/bin/bash
#
# Create additional Druid users via API
# Run this AFTER Druid has started successfully
#

set -e

source /etc/druid/druid.env

ROUTER_URL="http://localhost:8888"
MAX_ATTEMPTS=30
ATTEMPT=0

echo "Waiting for Druid to be ready..."

# Wait for Druid to start
while [ \$ATTEMPT -lt \$MAX_ATTEMPTS ]; do
    if curl -s -f \$ROUTER_URL/status/health > /dev/null 2>&1; then
        echo "Druid is ready!"
        break
    fi
    ATTEMPT=\$((ATTEMPT + 1))
    echo "Attempt \$ATTEMPT/\$MAX_ATTEMPTS: Waiting for Druid to start..."
    sleep 10
done

if [ \$ATTEMPT -eq \$MAX_ATTEMPTS ]; then
    echo "ERROR: Druid did not start within expected time"
    exit 1
fi

echo ""
echo "Creating read-only user: \$DRUID_READONLY_USER"

# Create the read-only user
curl -X POST -H 'Content-Type: application/json' \\
  -u "\$DRUID_ADMIN_USER:\$DRUID_ADMIN_PASSWORD" \\
  -d '{"userName":"'\$DRUID_READONLY_USER'","password":"'\$DRUID_READONLY_PASSWORD'"}' \\
  \$ROUTER_URL/druid-ext/basic-security/authentication/db/MyBasicMetadataAuthenticator/users/\$DRUID_READONLY_USER

echo ""
echo "Setting read-only permissions..."

# Grant read permissions to datasources
curl -X POST -H 'Content-Type: application/json' \\
  -u "\$DRUID_ADMIN_USER:\$DRUID_ADMIN_PASSWORD" \\
  -d '[{"resource":{"name":".*","type":"DATASOURCE"},"action":"READ"}]' \\
  \$ROUTER_URL/druid-ext/basic-security/authorization/db/MyBasicMetadataAuthorizer/users/\$DRUID_READONLY_USER/permissions

# Grant state read permissions
curl -X POST -H 'Content-Type: application/json' \\
  -u "\$DRUID_ADMIN_USER:\$DRUID_ADMIN_PASSWORD" \\
  -d '[{"resource":{"name":"STATE","type":"STATE"},"action":"READ"}]' \\
  \$ROUTER_URL/druid-ext/basic-security/authorization/db/MyBasicMetadataAuthorizer/users/\$DRUID_READONLY_USER/permissions

echo ""
echo "✓ Read-only user '\$DRUID_READONLY_USER' created successfully!"
echo ""
echo "You can now login with:"
echo "  Username: \$DRUID_READONLY_USER"
echo "  Password: \$DRUID_READONLY_PASSWORD"
echo ""
EOF

        chmod +x "$DRUID_HOME/bin/create-users.sh"
        chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/bin/create-users.sh"
    fi
    
    log "Management scripts created"
}

# ============================================
# Configure Firewall
# ============================================
configure_firewall() {
    log "Configuring firewall (localhost-only access)..."
    
    if command -v ufw &> /dev/null; then
        ufw --force enable > /dev/null 2>&1
        ufw default deny incoming > /dev/null 2>&1
        ufw default allow outgoing > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        log "UFW firewall configured"
    elif command -v firewall-cmd &> /dev/null; then
        systemctl start firewalld > /dev/null 2>&1
        systemctl enable firewalld > /dev/null 2>&1
        firewall-cmd --set-default-zone=drop --permanent > /dev/null 2>&1
        firewall-cmd --zone=drop --add-service=ssh --permanent > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log "Firewalld configured"
    else
        warning "No firewall found. Services bound to localhost only."
    fi
}

# ============================================
# Create Documentation
# ============================================
create_documentation() {
    log "Creating documentation..."
    
    cat > "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF
================================================================================
Apache Druid Secure Installation
================================================================================
Installation Date: $(date)
Druid Version: $DRUID_VERSION

AUTHENTICATION CREDENTIALS
================================================================================
Admin Username: $ADMIN_USER
Admin Password: $ADMIN_PASSWORD

EOF

    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF
Read-Only Username: $READONLY_USER
Read-Only Password: $READONLY_PASSWORD

EOF
    fi

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF
Internal System Password: $INTERNAL_PASSWORD

⚠️  IMPORTANT: Save these credentials securely!
All credentials are also stored in: /etc/druid/druid.env (600 permissions)

IMPORTANT: CREATING ADDITIONAL USERS
================================================================================
The admin user 'admin' is created automatically when Druid starts.
EOF

    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF

The read-only user '$READONLY_USER' must be created AFTER Druid starts:

1. Start Druid: sudo systemctl start druid
2. Wait for Druid to be ready (2-3 minutes)
3. Run: sudo -u druid $DRUID_HOME/bin/create-users.sh

This will create the read-only user with appropriate permissions.
EOF
    fi

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF

WEB CONSOLE ACCESS
================================================================================
Local: http://localhost:8888
Remote: ssh -L 8888:localhost:8888 $DRUID_USER@$(hostname -I | awk '{print $1}')

SERVICE MANAGEMENT
================================================================================
Start:   sudo systemctl start druid
Stop:    sudo systemctl stop druid
Status:  sudo systemctl status druid
Logs:    sudo journalctl -u druid -f

HEALTH CHECK
================================================================================
$DRUID_HOME/bin/check-status.sh

NEXT STEPS
================================================================================
1. sudo systemctl start druid
2. Wait 2-3 minutes for Druid to fully start
3. $DRUID_HOME/bin/check-status.sh
EOF

    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF
4. sudo -u druid $DRUID_HOME/bin/create-users.sh  # Create read-only user
5. Access via SSH tunnel
6. Login with admin or read-only credentials
EOF
    else
        cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF
4. Access via SSH tunnel
5. Login with admin credentials
EOF
    fi

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << EOF

Documentation: https://druid.apache.org/docs/latest/
EOF

    chmod 600 "$DRUID_HOME/INSTALLATION_INFO.txt"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/INSTALLATION_INFO.txt"
}

# ============================================
# Final Setup
# ============================================
final_setup() {
    log "Performing final setup..."
    
    chown -R $DRUID_USER:$DRUID_GROUP "$DRUID_HOME"
    chown -R $DRUID_USER:$DRUID_GROUP "$DATA_DIR"
    chown -R $DRUID_USER:$DRUID_GROUP "$LOG_DIR"
    
    log "Final setup completed"
}

# ============================================
# Main Installation Flow
# ============================================
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║         Apache Druid Secure Installation Script               ║"
    echo "║         Production-Ready Configuration                        ║"
    echo "║         WITH: Old Version Cleanup & User Recreation           ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    check_root
    detect_os
    
    info "This script will:"
    echo "  • Clean up any existing Druid installations"
    echo "  • Remove and recreate the Druid system user"
    echo "  • Auto-detect and install the latest Druid version"
    echo "  • Configure authentication and authorization"
    echo "  • Bind all services to localhost (127.0.0.1) for security"
    echo "  • Set up systemd service management"
    echo "  • Configure firewall rules"
    echo ""
    
    CONTINUE=$(read_from_tty "Continue with installation? (y/n): ")
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    echo ""
    
    # NEW: Cleanup old installation first
    cleanup_old_installation
    
    install_dependencies
    get_latest_version
    create_user
    download_druid
    create_directories
    prompt_credentials
    configure_security
    configure_services
    create_systemd_services
    create_management_scripts
    configure_firewall
    create_documentation
    final_setup
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║              Installation Completed Successfully!             ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    log "Apache Druid $DRUID_VERSION installed successfully!"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                   IMPORTANT CREDENTIALS                        ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Admin Username: $ADMIN_USER"
    echo "  Admin Password: $ADMIN_PASSWORD"
    echo ""
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        echo "  Read-Only Username: $READONLY_USER"
        echo "  Read-Only Password: $READONLY_PASSWORD"
        echo "  (User will be created after Druid starts)"
        echo ""
    fi
    echo "  ⚠️  Save these credentials securely!"
    echo "  Also saved to: /etc/druid/druid.env and $DRUID_HOME/INSTALLATION_INFO.txt"
    echo ""
    info "Quick Start:"
    echo ""
    echo "  1. Start Druid:"
    echo "     sudo systemctl start druid"
    echo ""
    echo "  2. Wait 2-3 minutes, then check status:"
    echo "     $DRUID_HOME/bin/check-status.sh"
    echo ""
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        echo "  3. Create read-only user (after Druid is ready):"
        echo "     sudo -u druid $DRUID_HOME/bin/create-users.sh"
        echo ""
        echo "  4. Access Web Console (SSH tunnel):"
    else
        echo "  3. Access Web Console (SSH tunnel):"
    fi
    echo "     ssh -L 8888:localhost:8888 $DRUID_USER@$(hostname -I | awk '{print $1}')"
    echo "     Then open: http://localhost:8888"
    echo ""
    info "Full documentation: $DRUID_HOME/INSTALLATION_INFO.txt"
    echo ""
}

main "$@"
