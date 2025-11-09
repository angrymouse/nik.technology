#!/bin/bash
#
# Apache Druid Secure Installation Script - FIXED VERSION
# Auto-detects latest version, configures security, creates systemd services
# FIXES: Proper credential handling, metadata cleanup, password verification
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
    
    if [ -f "$DATA_DIR/metadata.db/service.properties" ]; then
        found_old=1
        warning "Found existing Druid metadata database"
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
    warning "  ⚠️  METADATA DATABASE OPTIONS:"
    echo ""
    
    CLEAN_METADATA=$(read_from_tty "Clean metadata database (REQUIRED for new passwords)? (y/n) [y]: ")
    CLEAN_METADATA=${CLEAN_METADATA:-y}
    
    if [[ "$CLEAN_METADATA" =~ ^[Yy]$ ]]; then
        warning "  ✓ Metadata database will be DELETED (fresh start with new credentials)"
        warning "  ✓ ALL existing datasources and user accounts will be LOST"
        CLEAN_DATA_DIR=true
    else
        warning "  ✗ Metadata database will be PRESERVED"
        warning "  ✗ Old user credentials will remain - new passwords will NOT work!"
        warning "  ✗ You'll need to use your OLD passwords to login"
        CLEAN_DATA_DIR=false
    fi
    
    echo ""
    CLEANUP=$(read_from_tty "Continue with cleanup? (y/n): ")
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
    
    # Clean metadata database if requested
    if [ "$CLEAN_DATA_DIR" = true ]; then
        log "Cleaning metadata database and data directory..."
        if [ -d "$DATA_DIR" ]; then
            # Backup data dir just in case
            BACKUP_DATA_DIR="$DATA_DIR-backup-$(date +%Y%m%d-%H%M%S)"
            log "Backing up data directory to $BACKUP_DATA_DIR..."
            mv "$DATA_DIR" "$BACKUP_DATA_DIR" 2>/dev/null || rm -rf "$DATA_DIR"
        fi
        log "Metadata database cleaned - new credentials will work"
    else
        log "Preserving metadata database - old credentials will remain active"
    fi
    
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
    
    # Fix permissions immediately after extraction
    log "Setting up permissions and directories..."
    
    # Make all bin scripts executable
    chmod +x "$INSTALL_DIR/apache-druid-${DRUID_VERSION}/bin"/*
    
    # Create required directories
    mkdir -p "$INSTALL_DIR/apache-druid-${DRUID_VERSION}/log"
    mkdir -p "$INSTALL_DIR/apache-druid-${DRUID_VERSION}/var"
    
    # Set ownership to druid user
    chown -R $DRUID_USER:$DRUID_GROUP "$INSTALL_DIR/apache-druid-${DRUID_VERSION}"
    chown -R $DRUID_USER:$DRUID_GROUP "$DRUID_HOME"
    
    # Ensure directories are writable
    chmod 755 "$INSTALL_DIR/apache-druid-${DRUID_VERSION}/log"
    chmod 755 "$INSTALL_DIR/apache-druid-${DRUID_VERSION}/var"
    
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
    mkdir -p "$DRUID_HOME/var"  # Required for systemd mount namespacing
    
    chown -R $DRUID_USER:$DRUID_GROUP "$DATA_DIR"
    chown -R $DRUID_USER:$DRUID_GROUP "$LOG_DIR"
    chown -R $DRUID_USER:$DRUID_GROUP "$DRUID_HOME"
    
    chmod 700 "$DATA_DIR"
    chmod -R 700 "$DATA_DIR"/*
    chmod 750 "$LOG_DIR"
    chmod 755 "$DRUID_HOME/var"
    
    log "Directory structure created with secure permissions"
}

# ============================================
# Prompt for Port Configuration
# ============================================
prompt_ports() {
    log "Configuring service ports..."
    echo ""
    
    info "Default Druid Ports:"
    echo "  ZooKeeper Client:    2181"
    echo "  ZooKeeper Admin:     8080"
    echo "  Router (API):        8888"
    echo "  Coordinator:         8081"
    echo "  Broker:              8082"
    echo "  Historical:          8083"
    echo "  MiddleManager:       8091"
    echo ""
    
    CUSTOMIZE_PORTS=$(read_from_tty "Customize ports? (y/n) [n]: ")
    CUSTOMIZE_PORTS=${CUSTOMIZE_PORTS:-n}
    
    if [[ "$CUSTOMIZE_PORTS" =~ ^[Yy]$ ]]; then
        echo ""
        info "Enter custom ports (press Enter to use default):"
        echo ""
        
        ZK_PORT=$(read_from_tty "ZooKeeper Client Port [2181]: ")
        ZK_PORT=${ZK_PORT:-2181}
        
        ZK_ADMIN_PORT=$(read_from_tty "ZooKeeper Admin Port [8080]: ")
        ZK_ADMIN_PORT=${ZK_ADMIN_PORT:-8080}
        
        ROUTER_PORT=$(read_from_tty "Router Port [8888]: ")
        ROUTER_PORT=${ROUTER_PORT:-8888}
        
        COORDINATOR_PORT=$(read_from_tty "Coordinator Port [8081]: ")
        COORDINATOR_PORT=${COORDINATOR_PORT:-8081}
        
        BROKER_PORT=$(read_from_tty "Broker Port [8082]: ")
        BROKER_PORT=${BROKER_PORT:-8082}
        
        HISTORICAL_PORT=$(read_from_tty "Historical Port [8083]: ")
        HISTORICAL_PORT=${HISTORICAL_PORT:-8083}
        
        MIDDLEMANAGER_PORT=$(read_from_tty "MiddleManager Port [8091]: ")
        MIDDLEMANAGER_PORT=${MIDDLEMANAGER_PORT:-8091}
    else
        ZK_PORT=2181
        ZK_ADMIN_PORT=8080
        ROUTER_PORT=8888
        COORDINATOR_PORT=8081
        BROKER_PORT=8082
        HISTORICAL_PORT=8083
        MIDDLEMANAGER_PORT=8091
    fi
    
    echo ""
    
    # Check if ports are in use
    log "Checking if ports are available..."
    PORTS_IN_USE=""
    
    for port in $ZK_PORT $ZK_ADMIN_PORT $ROUTER_PORT $COORDINATOR_PORT $BROKER_PORT $HISTORICAL_PORT $MIDDLEMANAGER_PORT; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            PORTS_IN_USE="$PORTS_IN_USE $port"
            warning "Port $port is already in use!"
        fi
    done
    
    if [ -n "$PORTS_IN_USE" ]; then
        echo ""
        error "The following ports are already in use:$PORTS_IN_USE"
        echo ""
        echo "Processes using these ports:"
        for port in $PORTS_IN_USE; do
            echo "Port $port:"
            sudo netstat -tulnp 2>/dev/null | grep ":$port " || true
        done
        echo ""
        CONTINUE=$(read_from_tty "Continue anyway? (y/n) [n]: ")
        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            error "Installation cancelled. Please free up the ports or choose different ports."
            exit 1
        fi
    fi
    
    echo ""
    log "Port configuration completed"
    log "ZooKeeper Client: $ZK_PORT, Admin: $ZK_ADMIN_PORT"
    log "Router: $ROUTER_PORT, Coordinator: $COORDINATOR_PORT"
    log "Broker: $BROKER_PORT, Historical: $HISTORICAL_PORT, MiddleManager: $MIDDLEMANAGER_PORT"
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
    
    # Save all credentials to env file (used by systemd)
    cat > /etc/druid/druid.env << 'ENVEOF'
# Druid Security Environment Variables
# DO NOT SHARE THIS FILE - Contains sensitive credentials
ENVEOF
    
    # Append credentials (avoiding any command substitution in heredoc)
    echo "# Generated: $(date)" >> /etc/druid/druid.env
    echo "" >> /etc/druid/druid.env
    echo "DRUID_ADMIN_USER=${ADMIN_USER}" >> /etc/druid/druid.env
    echo "DRUID_ADMIN_PASSWORD=${ADMIN_PASSWORD}" >> /etc/druid/druid.env
    echo "DRUID_INTERNAL_PASSWORD=${INTERNAL_PASSWORD}" >> /etc/druid/druid.env

    # Add readonly user if configured
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        echo "DRUID_READONLY_USER=${READONLY_USER}" >> /etc/druid/druid.env
        echo "DRUID_READONLY_PASSWORD=${READONLY_PASSWORD}" >> /etc/druid/druid.env
    fi
    
    chmod 600 /etc/druid/druid.env
    chown $DRUID_USER:$DRUID_GROUP /etc/druid/druid.env
    
    # Also create a runtime properties extension file that will be sourced
    cat > /etc/druid/runtime.env << 'RUNTIMEEOF'
# Druid Runtime Environment
# This file is sourced to ensure passwords are available
RUNTIMEEOF
    echo "export DRUID_ADMIN_PASSWORD='${ADMIN_PASSWORD}'" >> /etc/druid/runtime.env
    echo "export DRUID_INTERNAL_PASSWORD='${INTERNAL_PASSWORD}'" >> /etc/druid/runtime.env
    
    chmod 600 /etc/druid/runtime.env
    chown $DRUID_USER:$DRUID_GROUP /etc/druid/runtime.env
    
    cp -r "$DRUID_HOME/conf" /etc/druid/backup/
    
    # Store config generation date
    local CONFIG_DATE=$(date)
    
    # CRITICAL FIX: Use actual password values instead of environment variable references
    # Druid's initialAdminPassword/initialInternalClientPassword don't support ${env:} syntax reliably
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties" << 'CONFIGEOF'
#
# Apache Druid - Secure Production Configuration
CONFIGEOF
    echo "# Generated: ${CONFIG_DATE}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    cat >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties" << 'CONFIGEOF'
#

# Extensions (REQUIRED for security)
druid.extensions.loadList=["druid-basic-security", "druid-histogram", "druid-datasketches", "druid-kafka-indexing-service", "mysql-metadata-storage", "postgresql-metadata-storage"]

# Logging
druid.startup.logging.logProperties=true
druid.startup.logging.maskProperties=["password", "key", "secret", "token"]
CONFIGEOF
    
    # Add ZooKeeper config with port substitution
    echo "" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    echo "# Zookeeper" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    echo "druid.zk.service.host=localhost:${ZK_PORT}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    echo "druid.zk.paths.base=/druid" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    
    cat >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties" << 'CONFIGEOF'

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

# Host binding (0.0.0.0 for external API access via Router)
druid.host=0.0.0.0
druid.bindOnHost=true

# Authentication - Basic Auth with Metadata Store
druid.auth.authenticatorChain=["MyBasicMetadataAuthenticator"]
druid.auth.authenticator.MyBasicMetadataAuthenticator.type=basic

# CRITICAL: These passwords are used ONLY on first startup with empty metadata
# Using literal values instead of env vars for better compatibility
CONFIGEOF
    
    # Add passwords separately to avoid any substitution issues
    echo "druid.auth.authenticator.MyBasicMetadataAuthenticator.initialAdminPassword=${ADMIN_PASSWORD}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    echo "druid.auth.authenticator.MyBasicMetadataAuthenticator.initialInternalClientPassword=${INTERNAL_PASSWORD}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    
    cat >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties" << 'CONFIGEOF'

druid.auth.authenticator.MyBasicMetadataAuthenticator.credentialsValidator.type=metadata
druid.auth.authenticator.MyBasicMetadataAuthenticator.skipOnFailure=false
druid.auth.authenticator.MyBasicMetadataAuthenticator.authorizerName=MyBasicMetadataAuthorizer

# Authorization
druid.auth.authorizers=["MyBasicMetadataAuthorizer"]
druid.auth.authorizer.MyBasicMetadataAuthorizer.type=basic

# Escalator (internal system authentication)
druid.escalator.type=basic
druid.escalator.internalClientUsername=druid_system
CONFIGEOF
    
    echo "druid.escalator.internalClientPassword=${INTERNAL_PASSWORD}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    
    cat >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties" << 'CONFIGEOF'
druid.escalator.authorizerName=MyBasicMetadataAuthorizer

# Security Hardening
druid.server.http.showDetailedJettyErrors=false
druid.request.logging.type=slf4j
druid.javascript.enabled=false
druid.sql.planner.authorizeSystemTablesDirectly=true
CONFIGEOF
    
    chmod 600 "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties"
    
    # Configure ZooKeeper with custom ports
    log "Configuring ZooKeeper..."
    
    mkdir -p "$DRUID_HOME/conf/zk"
    cat > "$DRUID_HOME/conf/zk/zoo.cfg" << 'ZKEOF'
# ZooKeeper Configuration
tickTime=2000
ZKEOF
    echo "dataDir=${DATA_DIR}/zk" >> "$DRUID_HOME/conf/zk/zoo.cfg"
    echo "clientPort=${ZK_PORT}" >> "$DRUID_HOME/conf/zk/zoo.cfg"
    cat >> "$DRUID_HOME/conf/zk/zoo.cfg" << 'ZKEOF'
maxClientCnxns=60
admin.enableServer=true
ZKEOF
    echo "admin.serverPort=${ZK_ADMIN_PORT}" >> "$DRUID_HOME/conf/zk/zoo.cfg"
    echo "4lw.commands.whitelist=*" >> "$DRUID_HOME/conf/zk/zoo.cfg"
    
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/conf/zk/zoo.cfg"
    
    log "Security configuration completed"
}

# ============================================
# Configure Service-Specific Settings
# ============================================
configure_services() {
    log "Configuring individual Druid services..."
    
    # Router configuration
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/router/runtime.properties" << 'ROUTEREOF'
druid.service=druid/router
druid.host=0.0.0.0
druid.server.http.bindAddress=0.0.0.0
druid.router.http.numConnections=50
druid.router.http.readTimeout=PT5M
druid.router.http.numMaxThreads=100
druid.server.http.numThreads=100
druid.router.managementProxy.enabled=true
druid.router.sql.enable=true
ROUTEREOF
    echo "druid.plaintextPort=${ROUTER_PORT}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/router/runtime.properties"

    # Coordinator configuration
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties" << 'COORDINATOREOF'
druid.service=druid/coordinator
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.coordinator.startDelay=PT10S
druid.coordinator.period=PT30S
druid.indexer.queue.startDelay=PT5S
druid.indexer.runner.type=local
druid.indexer.storage.type=metadata
COORDINATOREOF
    echo "druid.plaintextPort=${COORDINATOR_PORT}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties"

    # Broker configuration
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/broker/runtime.properties" << 'BROKEREOF'
druid.service=druid/broker
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
BROKEREOF
    echo "druid.plaintextPort=${BROKER_PORT}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/broker/runtime.properties"

    # Historical configuration
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/historical/runtime.properties" << 'HISTORICALEOF'
druid.service=druid/historical
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.processing.buffer.sizeBytes=134217728
druid.processing.numThreads=1
druid.processing.numMergeBuffers=1
druid.segmentCache.locations=[{"path":"/var/druid/segment-cache","maxSize":1073741824}]
druid.segmentCache.infoDir=/var/druid/segment-cache-info
druid.server.maxSize=1073741824
HISTORICALEOF
    echo "druid.plaintextPort=${HISTORICAL_PORT}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/historical/runtime.properties"

    # MiddleManager configuration
    cat > "$DRUID_HOME/conf/druid/single-server/nano-quickstart/middleManager/runtime.properties" << 'MIDDLEEOF'
druid.service=druid/middleManager
druid.host=127.0.0.1
druid.server.http.bindAddress=127.0.0.1
druid.indexer.runner.javaOpts=-server -Xms256m -Xmx256m -XX:MaxDirectMemorySize=256m -Duser.timezone=UTC -Dfile.encoding=UTF-8 -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager -Djava.io.tmpdir=/var/druid/tmp
druid.indexer.task.baseTaskDir=/var/druid/task
druid.indexer.task.restoreTasksOnRestart=false
druid.worker.capacity=2
druid.indexer.fork.property.druid.processing.numThreads=1
druid.indexer.fork.property.druid.processing.buffer.sizeBytes=134217728
MIDDLEEOF
    echo "druid.plaintextPort=${MIDDLEMANAGER_PORT}" >> "$DRUID_HOME/conf/druid/single-server/nano-quickstart/middleManager/runtime.properties"
    
    log "Service-specific configurations completed"
}

# ============================================
# Create Systemd Service Files
# ============================================
create_systemd_services() {
    log "Creating systemd service files..."
    
    # Detect Java home
    JAVA_HOME_PATH=$(dirname $(dirname $(readlink -f $(which java))))
    log "Detected Java home: $JAVA_HOME_PATH"
    
    cat > /etc/systemd/system/druid.service << 'SERVICEEOF'
[Unit]
Description=Apache Druid (All Services - nano-quickstart)
Documentation=https://druid.apache.org/docs/latest/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=druid
Group=druid
EnvironmentFile=/etc/druid/druid.env
SERVICEEOF
    
    echo "Environment=\"DRUID_JAVA_HOME=${JAVA_HOME_PATH}\"" >> /etc/systemd/system/druid.service
    echo "WorkingDirectory=${DRUID_HOME}" >> /etc/systemd/system/druid.service
    echo "ExecStart=${DRUID_HOME}/bin/start-nano-quickstart" >> /etc/systemd/system/druid.service
    
    cat >> /etc/systemd/system/druid.service << 'SERVICEEOF'
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=30s
TimeoutStartSec=300
TimeoutStopSec=300

# Resource Limits
LimitNOFILE=65536
LimitNPROC=32768

# Security Hardening (relaxed for compatibility)
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=druid

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    
    log "Systemd service created: druid.service"
}

# ============================================
# Create Management Scripts
# ============================================
create_management_scripts() {
    log "Creating management scripts..."
    
    # Create check-status script
    cat > "$DRUID_HOME/bin/check-status.sh" << 'STATUSEOF'
#!/bin/bash
echo "Checking Druid services health..."
echo ""

STATUSEOF
    
    echo "services=(\"coordinator:${COORDINATOR_PORT}\" \"broker:${BROKER_PORT}\" \"historical:${HISTORICAL_PORT}\" \"router:${ROUTER_PORT}\" \"middleManager:${MIDDLEMANAGER_PORT}\")" >> "$DRUID_HOME/bin/check-status.sh"
    
    cat >> "$DRUID_HOME/bin/check-status.sh" << 'STATUSEOF'

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
STATUSEOF
    
    echo "echo \"Web Console: http://localhost:${ROUTER_PORT}\"" >> "$DRUID_HOME/bin/check-status.sh"
    echo "echo \"Use SSH tunnel for remote access: ssh -L ${ROUTER_PORT}:localhost:${ROUTER_PORT} user@server\"" >> "$DRUID_HOME/bin/check-status.sh"

    chmod +x "$DRUID_HOME/bin/check-status.sh"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/bin/check-status.sh"
    
    # Create credential verification script
    cat > "$DRUID_HOME/bin/verify-credentials.sh" << 'VERIFYEOF'
#!/bin/bash
# Verify admin credentials work

source /etc/druid/druid.env

VERIFYEOF
    
    echo "ROUTER_URL=\"http://localhost:${ROUTER_PORT}\"" >> "$DRUID_HOME/bin/verify-credentials.sh"
    
    cat >> "$DRUID_HOME/bin/verify-credentials.sh" << 'VERIFYEOF'
MAX_ATTEMPTS=60
ATTEMPT=0

echo "Waiting for Druid Router to be ready..."

# Wait for Router to start
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if curl -s -f $ROUTER_URL/status/health > /dev/null 2>&1; then
        echo "✓ Router is ready!"
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: Waiting..."
    sleep 5
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo "✗ ERROR: Router did not start within expected time"
    exit 1
fi

echo ""
echo "Testing admin credentials..."
echo "Username: $DRUID_ADMIN_USER"
echo "Password: (hidden)"
echo ""

# Try to authenticate
RESPONSE=$(curl -s -w "\n%{http_code}" -u "$DRUID_ADMIN_USER:$DRUID_ADMIN_PASSWORD" \
    "$ROUTER_URL/druid/coordinator/v1/loadstatus" 2>/dev/null)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ SUCCESS! Admin credentials are working!"
    echo ""
    echo "You can now login with:"
    echo "  Username: $DRUID_ADMIN_USER"
    echo "  Password: $DRUID_ADMIN_PASSWORD"
    echo ""
    exit 0
elif [ "$HTTP_CODE" = "401" ]; then
    echo "✗ FAILURE! Authentication failed (401 Unauthorized)"
    echo ""
    echo "This means:"
    echo "  1. The metadata database may contain old credentials"
    echo "  2. You need to use the OLD password from a previous installation"
    echo "  3. OR delete /var/druid and reinstall to use new credentials"
    echo ""
    exit 1
else
    echo "✗ FAILURE! Unexpected response (HTTP $HTTP_CODE)"
    echo ""
    echo "Full response:"
    echo "$RESPONSE" | head -n-1
    echo ""
    exit 1
fi
VERIFYEOF
    
    chmod +x "$DRUID_HOME/bin/verify-credentials.sh"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/bin/verify-credentials.sh"
    
    # Create permission fix script
    cat > "$DRUID_HOME/bin/fix-permissions.sh" << 'FIXEOF'
#!/bin/bash
# Fix Druid permissions if startup fails
echo "Fixing Druid permissions..."

sudo systemctl stop druid 2>/dev/null || true

# Make all scripts executable
sudo chmod +x /opt/druid/bin/* 2>/dev/null || true

# Create and fix directories
sudo mkdir -p /opt/druid/log /opt/druid/var
sudo mkdir -p /opt/apache-druid-*/log /opt/apache-druid-*/var 2>/dev/null || true

# Fix ownership
sudo chown -R druid:druid /opt/druid
sudo chown -R druid:druid /opt/apache-druid-* 2>/dev/null || true
sudo chown -R druid:druid /var/druid
sudo chown -R druid:druid /var/log/druid

# Fix permissions
sudo chmod 755 /opt/druid/log /opt/druid/var
sudo chmod 755 /opt/apache-druid-*/log /opt/apache-druid-*/var 2>/dev/null || true

echo "✓ Permissions fixed!"
echo ""
echo "Starting Druid..."
sudo systemctl start druid

echo "Wait 2-3 minutes, then check:"
echo "  /opt/druid/bin/check-status.sh"
FIXEOF

    chmod +x "$DRUID_HOME/bin/fix-permissions.sh"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/bin/fix-permissions.sh"
    
    # Create password reset helper
    cat > "$DRUID_HOME/bin/reset-password.sh" << 'RESETEOF'
#!/bin/bash
# Reset admin password via metadata database cleanup

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           Druid Admin Password Reset Tool                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "⚠️  WARNING: This will reset the metadata database!"
echo "⚠️  ALL datasources and user accounts will be lost!"
echo ""

read -p "Continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Stopping Druid..."
sudo systemctl stop druid

echo "Backing up current metadata..."
BACKUP_DIR="/var/druid-backup-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p "$BACKUP_DIR"
sudo cp -r /var/druid "$BACKUP_DIR/" 2>/dev/null || true

echo "Removing metadata database..."
sudo rm -rf /var/druid/metadata.db

echo "Starting Druid with fresh metadata..."
sudo systemctl start druid

echo ""
echo "✓ Password reset initiated!"
echo ""
echo "Wait 2-3 minutes for Druid to start, then run:"
echo "  /opt/druid/bin/verify-credentials.sh"
echo ""
echo "The passwords from /etc/druid/druid.env will now work."
RESETEOF

    chmod +x "$DRUID_HOME/bin/reset-password.sh"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/bin/reset-password.sh"
    
    # Create user setup script (runs after Druid starts)
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        cat > "$DRUID_HOME/bin/create-users.sh" << 'USERSEOF'
#!/bin/bash
#
# Create additional Druid users via API
# Run this AFTER Druid has started successfully
#

set -e

source /etc/druid/druid.env

USERSEOF
        
        echo "ROUTER_URL=\"http://localhost:${ROUTER_PORT}\"" >> "$DRUID_HOME/bin/create-users.sh"
        
        cat >> "$DRUID_HOME/bin/create-users.sh" << 'USERSEOF'
MAX_ATTEMPTS=30
ATTEMPT=0

echo "Waiting for Druid to be ready..."

# Wait for Druid to start
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if curl -s -f $ROUTER_URL/status/health > /dev/null 2>&1; then
        echo "Druid is ready!"
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: Waiting for Druid to start..."
    sleep 10
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo "ERROR: Druid did not start within expected time"
    exit 1
fi

echo ""
echo "Creating read-only user: $DRUID_READONLY_USER"

# Create the read-only user
curl -X POST -H 'Content-Type: application/json' \
  -u "$DRUID_ADMIN_USER:$DRUID_ADMIN_PASSWORD" \
  -d '{"userName":"'$DRUID_READONLY_USER'","password":"'$DRUID_READONLY_PASSWORD'"}' \
  $ROUTER_URL/druid-ext/basic-security/authentication/db/MyBasicMetadataAuthenticator/users/$DRUID_READONLY_USER

echo ""
echo "Setting read-only permissions..."

# Grant read permissions to datasources
curl -X POST -H 'Content-Type: application/json' \
  -u "$DRUID_ADMIN_USER:$DRUID_ADMIN_PASSWORD" \
  -d '[{"resource":{"name":".*","type":"DATASOURCE"},"action":"READ"}]' \
  $ROUTER_URL/druid-ext/basic-security/authorization/db/MyBasicMetadataAuthorizer/users/$DRUID_READONLY_USER/permissions

# Grant state read permissions
curl -X POST -H 'Content-Type: application/json' \
  -u "$DRUID_ADMIN_USER:$DRUID_ADMIN_PASSWORD" \
  -d '[{"resource":{"name":"STATE","type":"STATE"},"action":"READ"}]' \
  $ROUTER_URL/druid-ext/basic-security/authorization/db/MyBasicMetadataAuthorizer/users/$DRUID_READONLY_USER/permissions

echo ""
echo "✓ Read-only user '$DRUID_READONLY_USER' created successfully!"
echo ""
echo "You can now login with:"
echo "  Username: $DRUID_READONLY_USER"
echo "  Password: $DRUID_READONLY_PASSWORD"
echo ""
USERSEOF

        chmod +x "$DRUID_HOME/bin/create-users.sh"
        chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/bin/create-users.sh"
    fi
    
    log "Management scripts created"
}

# ============================================
# Configure Firewall
# ============================================
configure_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw --force enable > /dev/null 2>&1
        ufw default deny incoming > /dev/null 2>&1
        ufw default allow outgoing > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        ufw allow $ROUTER_PORT/tcp comment 'Druid Router API' > /dev/null 2>&1
        log "UFW firewall configured - Port $ROUTER_PORT open for Druid API"
    elif command -v firewall-cmd &> /dev/null; then
        systemctl start firewalld > /dev/null 2>&1
        systemctl enable firewalld > /dev/null 2>&1
        firewall-cmd --permanent --zone=public --add-port=$ROUTER_PORT/tcp > /dev/null 2>&1
        firewall-cmd --permanent --zone=public --add-service=ssh > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log "Firewalld configured - Port $ROUTER_PORT open for Druid API"
    else
        warning "No firewall found. Port $ROUTER_PORT will be open if network allows."
        warning "Consider installing ufw (Ubuntu/Debian) or firewalld (RHEL/CentOS)"
    fi
    
    info "Druid Router API will be accessible on port $ROUTER_PORT"
}

# ============================================
# Create Documentation
# ============================================
create_documentation() {
    log "Creating documentation..."
    
    # Store generation date to avoid command substitution in heredoc
    local DOC_DATE=$(date)
    local SERVER_IP=$(hostname -I | awk '{print $1}')
    
    cat > "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
================================================================================
Apache Druid Secure Installation
================================================================================
DOCEOF
    
    echo "Installation Date: ${DOC_DATE}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Druid Version: ${DRUID_VERSION}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    
    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
AUTHENTICATION CREDENTIALS
================================================================================
DOCEOF
    
    echo "Admin Username: ${ADMIN_USER}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Admin Password: ${ADMIN_PASSWORD}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        echo "Read-Only Username: ${READONLY_USER}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "Read-Only Password: ${READONLY_PASSWORD}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    fi

    echo "Internal System Password: ${INTERNAL_PASSWORD}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
⚠️  IMPORTANT: Save these credentials securely!
All credentials are also stored in: /etc/druid/druid.env (600 permissions)

VERIFYING CREDENTIALS WORK
================================================================================
After starting Druid, run this to verify your admin password works:

DOCEOF
    
    echo "  sudo -u druid ${DRUID_HOME}/bin/verify-credentials.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "If credentials don't work, it means the metadata database had old credentials." >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "To reset: sudo -u druid ${DRUID_HOME}/bin/reset-password.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
IMPORTANT: CREATING ADDITIONAL USERS
================================================================================
The admin user 'admin' is created automatically when Druid starts.
DOCEOF

    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "The read-only user '${READONLY_USER}' must be created AFTER Druid starts:" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "1. Start Druid: sudo systemctl start druid" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "2. Wait for Druid to be ready (2-3 minutes)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "3. Verify admin works: sudo -u druid ${DRUID_HOME}/bin/verify-credentials.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "4. Run: sudo -u druid ${DRUID_HOME}/bin/create-users.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "This will create the read-only user with appropriate permissions." >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    fi
    
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'

API ACCESS (EXTERNAL)
================================================================================
DOCEOF
    
    echo "Druid Router API is accessible externally on port ${ROUTER_PORT}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Direct Access:" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  http://${SERVER_IP}:${ROUTER_PORT}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Web Console:" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  http://${SERVER_IP}:${ROUTER_PORT}/unified-console.html" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "SQL API Endpoint:" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  http://${SERVER_IP}:${ROUTER_PORT}/druid/v2/sql" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Native Query API:" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  http://${SERVER_IP}:${ROUTER_PORT}/druid/v2" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
⚠️  SECURITY: All requests require authentication (username/password)
DOCEOF
    echo "⚠️  Firewall configured to allow port ${ROUTER_PORT}" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
PORTS CONFIGURED
================================================================================
DOCEOF
    
    echo "Router (API):        ${ROUTER_PORT} (0.0.0.0 - External)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Coordinator:         ${COORDINATOR_PORT} (localhost)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Broker:              ${BROKER_PORT} (localhost)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Historical:          ${HISTORICAL_PORT} (localhost)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "MiddleManager:       ${MIDDLEMANAGER_PORT} (localhost)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "ZooKeeper Client:    ${ZK_PORT} (localhost)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "ZooKeeper Admin:     ${ZK_ADMIN_PORT} (localhost)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
SERVICE MANAGEMENT
================================================================================
Start:   sudo systemctl start druid
Stop:    sudo systemctl stop druid
Status:  sudo systemctl status druid
Logs:    sudo journalctl -u druid -f

HEALTH CHECK & VERIFICATION
================================================================================
DOCEOF
    
    echo "Check services: ${DRUID_HOME}/bin/check-status.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Verify login:   ${DRUID_HOME}/bin/verify-credentials.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
TROUBLESHOOTING
================================================================================
If Druid fails to start with permission errors:
DOCEOF
    echo "  ${DRUID_HOME}/bin/fix-permissions.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "If admin password doesn't work:" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  ${DRUID_HOME}/bin/reset-password.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  (This deletes metadata and starts fresh)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
Common issues:
  - Permission denied errors → Run fix-permissions.sh
  - Services unhealthy → Wait 2-3 minutes for startup
  - Login fails → Run verify-credentials.sh to diagnose
  - Old password works → Old metadata exists, run reset-password.sh
  - Check logs: sudo journalctl -u druid -f

EXAMPLE API USAGE
================================================================================
# Health check (no auth required)
DOCEOF
    echo "curl http://${SERVER_IP}:${ROUTER_PORT}/status/health" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "# SQL Query (with authentication)" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "curl -X POST -H 'Content-Type: application/json' \\" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  -u admin:YOUR_PASSWORD \\" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  -d '{\"query\":\"SELECT * FROM INFORMATION_SCHEMA.TABLES\"}' \\" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "  http://${SERVER_IP}:${ROUTER_PORT}/druid/v2/sql" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    cat >> "$DRUID_HOME/INSTALLATION_INFO.txt" << 'DOCEOF'
NEXT STEPS
================================================================================
1. sudo systemctl start druid
2. Wait 2-3 minutes for Druid to fully start
DOCEOF
    echo "3. ${DRUID_HOME}/bin/check-status.sh" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "4. ${DRUID_HOME}/bin/verify-credentials.sh  # VERIFY LOGIN WORKS!" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        echo "5. sudo -u druid ${DRUID_HOME}/bin/create-users.sh  # Create read-only user" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "6. Test API access from external client" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "7. Login to web console with admin or read-only credentials" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    else
        echo "5. Test API access from external client" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
        echo "6. Login to web console with admin credentials" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    fi
    
    echo "" >> "$DRUID_HOME/INSTALLATION_INFO.txt"
    echo "Documentation: https://druid.apache.org/docs/latest/" >> "$DRUID_HOME/INSTALLATION_INFO.txt"

    chmod 600 "$DRUID_HOME/INSTALLATION_INFO.txt"
    chown $DRUID_USER:$DRUID_GROUP "$DRUID_HOME/INSTALLATION_INFO.txt"
}

# ============================================
# Final Setup
# ============================================
final_setup() {
    log "Performing final setup and permission checks..."
    
    # Ensure all directories exist
    mkdir -p "$DRUID_HOME/var"
    mkdir -p "$DRUID_HOME/log"
    
    # Make all bin scripts executable
    chmod +x "$DRUID_HOME/bin"/* 2>/dev/null || true
    
    # Set comprehensive ownership
    chown -R $DRUID_USER:$DRUID_GROUP "$DRUID_HOME"
    chown -R $DRUID_USER:$DRUID_GROUP "$DATA_DIR"
    chown -R $DRUID_USER:$DRUID_GROUP "$LOG_DIR"
    
    # Verify critical directories are writable by druid user
    chmod 755 "$DRUID_HOME/log"
    chmod 755 "$DRUID_HOME/var"
    
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
    echo "║         FIXED: Proper Credential Handling & Verification      ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    check_root
    detect_os
    
    info "This script will:"
    echo "  • Clean up any existing Druid installations"
    echo "  • OPTIONALLY clean metadata database (required for new passwords)"
    echo "  • Auto-detect and install the latest Druid version"
    echo "  • Configure ports (customizable)"
    echo "  • Configure authentication with WORKING credentials"
    echo "  • Provide credential verification tools"
    echo "  • Set up systemd service management"
    echo "  • Configure firewall to allow Router port"
    echo ""
    warning "⚠️  Router API will be externally accessible - ensure strong passwords!"
    echo ""
    
    CONTINUE=$(read_from_tty "Continue with installation? (y/n): ")
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    echo ""
    
    cleanup_old_installation
    install_dependencies
    get_latest_version
    create_user
    download_druid
    create_directories
    prompt_ports
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
    echo "  3. VERIFY your password works:"
    echo "     sudo -u druid $DRUID_HOME/bin/verify-credentials.sh"
    echo ""
    if [[ "$CREATE_READONLY" =~ ^[Yy]$ ]]; then
        echo "  4. Create read-only user (after verification succeeds):"
        echo "     sudo -u druid $DRUID_HOME/bin/create-users.sh"
        echo ""
        echo "  5. Access Druid API (externally accessible on port $ROUTER_PORT):"
    else
        echo "  4. Access Druid API (externally accessible on port $ROUTER_PORT):"
    fi
    echo "     http://$(hostname -I | awk '{print $1}'):$ROUTER_PORT"
    echo ""
    info "API Endpoints:"
    echo "  Web Console: http://$(hostname -I | awk '{print $1}'):$ROUTER_PORT/unified-console.html"
    echo "  SQL API:     http://$(hostname -I | awk '{print $1}'):$ROUTER_PORT/druid/v2/sql"
    echo "  Native API:  http://$(hostname -I | awk '{print $1}'):$ROUTER_PORT/druid/v2"
    echo ""
    info "Configured Ports:"
    echo "  Router (API): $ROUTER_PORT"
    echo "  ZooKeeper:    $ZK_PORT (admin: $ZK_ADMIN_PORT)"
    echo ""
    warning "IMPORTANT: If passwords don't work, run:"
    echo "  sudo -u druid $DRUID_HOME/bin/reset-password.sh"
    echo ""
    info "Full documentation: $DRUID_HOME/INSTALLATION_INFO.txt"
    echo ""
}

main "$@"
