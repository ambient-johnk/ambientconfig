#!/bin/bash

# Linux System Configuration Script
# Functions: Hardware verification, Command checks, Netplan configuration, Volume formatting/mounting

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables for report generation
REPORT_MODE=false
REPORT_FILE=""
REPORT_DIR="/var/log/system-config-reports"

# Logging function
log() {
    local msg="${GREEN}[INFO]${NC} $1"
    echo -e "$msg"
    if $REPORT_MODE; then
        echo "[INFO] $1" >> "$REPORT_FILE"
    fi
}

error() {
    local msg="${RED}[ERROR]${NC} $1"
    echo -e "$msg"
    if $REPORT_MODE; then
        echo "[ERROR] $1" >> "$REPORT_FILE"
    fi
}

warn() {
    local msg="${YELLOW}[WARN]${NC} $1"
    echo -e "$msg"
    if $REPORT_MODE; then
        echo "[WARN] $1" >> "$REPORT_FILE"
    fi
}

info() {
    local msg="${BLUE}[INFO]${NC} $1"
    echo -e "$msg"
    if $REPORT_MODE; then
        echo "[INFO] $1" >> "$REPORT_FILE"
    fi
}

# Function to write section headers to report
report_section() {
    local section="$1"
    if $REPORT_MODE; then
        echo "" >> "$REPORT_FILE"
        echo "==========================================" >> "$REPORT_FILE"
        echo "$section" >> "$REPORT_FILE"
        echo "==========================================" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
}

# Function to capture command output to report
capture_output() {
    local output="$1"
    if $REPORT_MODE && [[ -n "$output" ]]; then
        echo "$output" >> "$REPORT_FILE"
    fi
}

# ============================================
# SECTION 1: Hardware Verification
# ============================================

check_network_interfaces() {
    report_section "NETWORK INTERFACES CHECK"
    log "Checking network interfaces..."
    
    # Expected interfaces (modify as needed)
    read -p "Enter expected interface names (space-separated, e.g., eth0 eth1 ens33): " expected_ifaces
    
    local failed=0
    for iface in $expected_ifaces; do
        if ip link show "$iface" &> /dev/null; then
            local state=$(ip link show "$iface" | grep -oP 'state \K\w+')
            local speed=""
            if [[ -f "/sys/class/net/$iface/speed" ]]; then
                speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo "N/A")
                if [[ "$speed" != "N/A" && "$speed" -gt 0 ]]; then
                    speed=" (${speed}Mbps)"
                else
                    speed=""
                fi
            fi
            log "Interface $iface: EXISTS - State: $state$speed"
        else
            error "Interface $iface: NOT FOUND"
            ((failed++))
        fi
    done
    
    # Show all available interfaces
    info "All available interfaces:"
    local iface_output=$(ip -br link show | grep -v "lo")
    echo "$iface_output" | while read line; do
        echo "  $line"
    done
    capture_output "$iface_output"
    
    return $failed
}

check_nvidia_gpu() {
    report_section "NVIDIA GPU CHECK"
    log "Checking NVIDIA GPU and drivers..."
    
    if ! command -v nvidia-smi &> /dev/null; then
        error "nvidia-smi not found - NVIDIA drivers may not be installed"
        return 1
    fi
    
    if nvidia-smi &> /dev/null; then
        log "NVIDIA driver loaded successfully"
        echo ""
        local gpu_output=$(nvidia-smi --query-gpu=index,name,driver_version,memory.total,temperature.gpu,power.draw --format=csv,noheader)
        echo "$gpu_output" | while IFS=, read idx name driver mem temp power; do
            info "GPU $idx: $name"
            info "  Driver: $driver"
            info "  Memory: $mem"
            info "  Temp: $temp"
            info "  Power: $power"
        done
        capture_output "$gpu_output"
        
        # Capture full nvidia-smi output for report
        if $REPORT_MODE; then
            echo "" >> "$REPORT_FILE"
            echo "Full nvidia-smi output:" >> "$REPORT_FILE"
            nvidia-smi >> "$REPORT_FILE" 2>&1
        fi
        echo ""
        return 0
    else
        error "nvidia-smi command failed - driver not properly loaded"
        return 1
    fi
}

check_cpu() {
    report_section "CPU INFORMATION"
    log "Checking CPU information..."
    
    local cpu_model=$(lscpu | grep "Model name" | cut -d: -f2 | xargs)
    local cpu_cores=$(lscpu | grep "^CPU(s):" | cut -d: -f2 | xargs)
    local cpu_threads=$(lscpu | grep "^Thread(s) per core:" | cut -d: -f2 | xargs)
    local cores_per_socket=$(lscpu | grep "Core(s) per socket:" | cut -d: -f2 | xargs)
    local sockets=$(lscpu | grep "Socket(s):" | cut -d: -f2 | xargs)
    local cpu_mhz=$(lscpu | grep "CPU MHz:" | cut -d: -f2 | xargs)
    local cpu_max_mhz=$(lscpu | grep "CPU max MHz:" | cut -d: -f2 | xargs)
    
    info "CPU Model: $cpu_model"
    info "Total Logical CPUs: $cpu_cores"
    info "Sockets: $sockets"
    info "Cores per Socket: $cores_per_socket"
    info "Threads per Core: $cpu_threads"
    info "Current Speed: ${cpu_mhz} MHz"
    if [[ -n "$cpu_max_mhz" ]]; then
        info "Max Speed: ${cpu_max_mhz} MHz"
    fi
    
    # Capture full lscpu output to report
    if $REPORT_MODE; then
        echo "" >> "$REPORT_FILE"
        echo "Full lscpu output:" >> "$REPORT_FILE"
        lscpu >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Check per-core frequencies
    info "Per-core current frequencies:"
    local freq_output=""
    for cpu in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
        if [[ -f "$cpu" ]]; then
            local core=$(echo "$cpu" | grep -oP 'cpu\K[0-9]+')
            local freq=$(cat "$cpu")
            local freq_mhz=$((freq / 1000))
            echo "  CPU$core: ${freq_mhz} MHz"
            freq_output+="CPU$core: ${freq_mhz} MHz\n"
        fi
    done
    capture_output "$freq_output"
    
    return 0
}

check_memory() {
    report_section "MEMORY CONFIGURATION"
    log "Checking memory configuration..."
    
    if ! command -v dmidecode &> /dev/null; then
        warn "dmidecode not found - install it for detailed memory info"
        info "Basic memory information:"
        free -h
        if $REPORT_MODE; then
            free -h >> "$REPORT_FILE"
        fi
        return 1
    fi
    
    local total_mem=$(free -h | grep "Mem:" | awk '{print $2}')
    info "Total System Memory: $total_mem"
    echo ""
    
    info "Memory modules installed:"
    local mem_output=$(dmidecode -t memory | grep -A 20 "Memory Device" | grep -E "Size:|Speed:|Type:|Locator:|Manufacturer:|Serial Number:|Part Number:" | while read line; do
        if echo "$line" | grep -q "Size:"; then
            echo ""
            echo "$line"
        elif echo "$line" | grep -q "No Module Installed"; then
            continue
        else
            echo "$line"
        fi
    done | grep -v "No Module Installed" -A 6)
    echo "$mem_output"
    
    # Capture to report
    if $REPORT_MODE; then
        echo "$mem_output" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "Full dmidecode memory output:" >> "$REPORT_FILE"
        dmidecode -t memory >> "$REPORT_FILE" 2>&1
    fi
    
    # Summary
    local slot_count=$(dmidecode -t memory | grep -c "Memory Device")
    local populated=$(dmidecode -t memory | grep "Size:" | grep -v "No Module Installed" | wc -l)
    echo ""
    info "Memory slots: $populated populated out of $slot_count total"
    
    return 0
}

check_power_supplies() {
    report_section "POWER SUPPLY INFORMATION"
    log "Checking power supply information..."
    
    local psu_info=""
    local found_psu=false
    
    # Check via dmidecode type 39 (System Power Supply)
    if command -v dmidecode &> /dev/null; then
        info "PSU information from dmidecode:"
        local dmi_output=$(dmidecode --type 39 2>/dev/null)
        
        if [[ -n "$dmi_output" ]] && ! echo "$dmi_output" | grep -q "No SMBIOS nor DMI entry point found"; then
            # Parse and display PSU information
            echo "$dmi_output" | grep -A 15 "System Power Supply" | while IFS= read -r line; do
                if echo "$line" | grep -qE "Location:|Name:|Manufacturer:|Serial Number:|Asset Tag:|Model Part Number:|Max Power Capacity:|Status:|Type:|Input Voltage Range Switching:"; then
                    echo "$line"
                    psu_info+="$line\n"
                    found_psu=true
                fi
            done
            
            # Capture full output to report
            if $REPORT_MODE; then
                echo "" >> "$REPORT_FILE"
                echo "Full dmidecode type 39 output:" >> "$REPORT_FILE"
                echo "$dmi_output" >> "$REPORT_FILE"
            fi
        else
            warn "No PSU information available in DMI/SMBIOS (Type 39)"
        fi
    else
        warn "dmidecode not found - cannot check PSU information"
    fi
    
    echo ""
    
    # Check via sysfs if available
    if [[ -d /sys/class/hwmon ]]; then
        info "Checking power sensors in sysfs:"
        local found_hwmon=false
        for hwmon in /sys/class/hwmon/hwmon*/name; do
            if [[ -f "$hwmon" ]]; then
                local name=$(cat "$hwmon")
                local dir=$(dirname "$hwmon")
                
                # Look for power inputs
                for power in "$dir"/power*_input; do
                    if [[ -f "$power" ]]; then
                        local watts=$(cat "$power")
                        watts=$((watts / 1000000))
                        local label_file="${power/input/label}"
                        local label="unknown"
                        if [[ -f "$label_file" ]]; then
                            label=$(cat "$label_file")
                        fi
                        info "  $name - $label: ${watts}W"
                        psu_info+="$name - $label: ${watts}W\n"
                        found_hwmon=true
                    fi
                done
            fi
        done
        if ! $found_hwmon; then
            info "  No power sensors found in sysfs"
        fi
    fi
    
    capture_output "$psu_info"
    
    echo ""
    read -p "Enter expected PSU wattages (space-separated, e.g., 750 750 for dual 750W): " expected_wattages
    
    if [[ -n "$expected_wattages" ]]; then
        info "Expected PSU configuration:"
        for watt in $expected_wattages; do
            info "  ${watt}W PSU"
        done
        if ! $found_psu; then
            warn "Manual verification recommended - check physical labels or BMC interface"
        fi
    fi
    
    return 0
}

check_raid_controller() {
    report_section "RAID CONTROLLER INFORMATION"
    log "Checking RAID controller configuration..."
    
    local found_controller=false
    local raid_output=""
    local raid_warnings=0
    
    # Check for MegaRAID (LSI/Broadcom/Avago)
    if command -v megacli &> /dev/null || command -v MegaCli64 &> /dev/null; then
        local megacli_cmd=$(command -v megacli || command -v MegaCli64)
        found_controller=true
        
        info "MegaRAID controller detected"
        
        # Get adapter info
        local adapter_info=$($megacli_cmd -AdpAllInfo -aALL | grep -E "Product Name|Memory Size|ROC temperature")
        echo "$adapter_info"
        raid_output+="$adapter_info\n"
        
        echo ""
        info "Checking BBU/Cache Vault status:"
        local bbu_full=$($megacli_cmd -AdpBbuCmd -GetBbuStatus -aALL)
        local bbu_info=$(echo "$bbu_full" | grep -E "Battery State|Charger Status|Temperature|Remaining Capacity|Voltage|Current")
        echo "$bbu_info"
        raid_output+="\nBBU Status:\n$bbu_info\n"
        
        # Check for BBU Optimal state
        local bbu_state=$(echo "$bbu_full" | grep "Battery State:" | awk '{print $3}')
        if [[ "$bbu_state" == "Optimal" ]]; then
            log "BBU Status: Optimal ✓"
        else
            error "BBU Status: $bbu_state - NOT OPTIMAL!"
            ((raid_warnings++))
            raid_output+="\n[ERROR] BBU is not in Optimal state: $bbu_state\n"
        fi
        
        echo ""
        info "Checking Virtual Drive cache settings:"
        local vd_info=$($megacli_cmd -LDInfo -Lall -aALL)
        
        # Display full VD table
        local vd_table=$($megacli_cmd -LDGetProp -Cache -LALL -aALL)
        echo "$vd_table"
        raid_output+="\nVirtual Drive Info:\n$vd_info\n"
        
        # Parse each virtual drive for cache policy
        echo ""
        info "Analyzing cache policies:"
        local ld_count=$($megacli_cmd -LDGetNum -aALL | grep "Number of Virtual Drives" | awk '{print $NF}')
        
        for ((ld=0; ld<ld_count; ld++)); do
            local cache_policy=$($megacli_cmd -LDGetProp -Cache -L${ld} -aALL | grep "Current Cache Policy")
            local vd_state=$($megacli_cmd -LDInfo -L${ld} -aALL | grep "State" | head -1 | awk '{print $NF}')
            
            echo "  VD ${ld}: State=$vd_state"
            echo "    $cache_policy"
            
            # Check for Optimal state
            if [[ "$vd_state" == "Optimal" ]]; then
                log "    VD ${ld} State: Optimal ✓"
            else
                error "    VD ${ld} State: $vd_state - NOT OPTIMAL!"
                ((raid_warnings++))
                raid_output+="\n[ERROR] VD ${ld} is not Optimal: $vd_state\n"
            fi
            
            # Check cache policy - look for WriteBack (RWTD is ideal)
            if echo "$cache_policy" | grep -q "WriteBack"; then
                if echo "$cache_policy" | grep -q "ReadAheadNone"; then
                    # RWBD - WriteBack with ReadAhead disabled (Battery Dependent mode)
                    warn "    VD ${ld} Cache: RWBD (WriteBack, Battery Dependent) - EXCEPTION!"
                    warn "    Cache may fall back to WriteThrough if BBU fails"
                    ((raid_warnings++))
                    raid_output+="\n[WARN] VD ${ld} Cache Policy: RWBD - Should be RWTD for optimal performance\n"
                elif echo "$cache_policy" | grep -q "ReadAhead"; then
                    # RWTD - WriteBack with ReadAhead (ideal)
                    log "    VD ${ld} Cache: RWTD (WriteThrough, Read Ahead) ✓"
                else
                    info "    VD ${ld} Cache: WriteBack enabled"
                fi
            elif echo "$cache_policy" | grep -q "WriteThrough"; then
                warn "    VD ${ld} Cache: WriteThrough mode - Performance impact!"
                ((raid_warnings++))
                raid_output+="\n[WARN] VD ${ld} Cache Policy: WriteThrough - Not optimal\n"
            fi
        done
        
        # Show summary table
        echo ""
        info "Virtual Drive Summary:"
        $megacli_cmd -LDGetProp -DskCache -LALL -aALL
        
        if $REPORT_MODE; then
            echo "" >> "$REPORT_FILE"
            echo "Full MegaCLI output:" >> "$REPORT_FILE"
            $megacli_cmd -AdpAllInfo -aALL >> "$REPORT_FILE" 2>&1
            echo "" >> "$REPORT_FILE"
            $megacli_cmd -AdpBbuCmd -GetBbuStatus -aALL >> "$REPORT_FILE" 2>&1
            echo "" >> "$REPORT_FILE"
            $megacli_cmd -LDInfo -Lall -aALL >> "$REPORT_FILE" 2>&1
        fi
        
    # Check for StorCLI (newer LSI/Broadcom)
    elif command -v storcli &> /dev/null || command -v storcli64 &> /dev/null; then
        local storcli_cmd=$(command -v storcli || command -v storcli64)
        found_controller=true
        
        info "RAID controller detected (StorCLI)"
        
        local controller_info=$($storcli_cmd /c0 show | grep -A 10 "Product Name\|Memory Size\|ROC temperature")
        echo "$controller_info"
        raid_output+="$controller_info\n"
        
        echo ""
        info "Checking BBU/CV status:"
        local bbu_cv_info=$($storcli_cmd /c0/cv show all 2>/dev/null || $storcli_cmd /c0/bbu show all 2>/dev/null)
        echo "$bbu_cv_info"
        raid_output+="\nBBU/CV Status:\n$bbu_cv_info\n"
        
        # Check BBU/CV state
        if echo "$bbu_cv_info" | grep -q "Optimal"; then
            log "BBU/CV Status: Optimal ✓"
        else
            local state=$(echo "$bbu_cv_info" | grep -i "state" | head -1)
            error "BBU/CV Status: $state - NOT OPTIMAL!"
            ((raid_warnings++))
            raid_output+="\n[ERROR] BBU/CV is not in Optimal state\n"
        fi
        
        echo ""
        info "Checking virtual drive cache settings:"
        local vd_cache=$($storcli_cmd /c0/vall show all)
        echo "$vd_cache" | grep -i "cache\|state"
        raid_output+="\nVD Cache:\n$vd_cache\n"
        
        # Check for cache policies
        if echo "$vd_cache" | grep -qi "WB"; then
            if echo "$vd_cache" | grep -qi "RWBD\|WriteBack.*NR"; then
                warn "Cache Policy: RWBD detected - EXCEPTION!"
                ((raid_warnings++))
                raid_output+="\n[WARN] Cache Policy: RWBD - Should be RWTD\n"
            else
                log "Cache Policy: WriteBack enabled ✓"
            fi
        else
            warn "Cache Policy: WriteThrough mode detected"
            ((raid_warnings++))
        fi
        
        if $REPORT_MODE; then
            echo "" >> "$REPORT_FILE"
            echo "Full StorCLI output:" >> "$REPORT_FILE"
            $storcli_cmd /c0 show all >> "$REPORT_FILE" 2>&1
        fi
        
    # Check for HP/HPE Smart Array
    elif command -v hpacucli &> /dev/null || command -v ssacli &> /dev/null; then
        local hpcli=$(command -v ssacli || command -v hpacucli)
        found_controller=true
        
        info "HP/HPE Smart Array controller detected"
        
        local hp_config=$($hpcli ctrl all show config)
        echo "$hp_config"
        raid_output+="$hp_config\n"
        
        echo ""
        info "Checking cache status:"
        local hp_cache=$($hpcli ctrl all show detail | grep -i cache)
        echo "$hp_cache"
        raid_output+="\nCache Status:\n$hp_cache\n"
        
        # Check array status
        if echo "$hp_config" | grep -q "OK"; then
            log "Array Status: OK ✓"
        else
            warn "Array Status: Check output above"
            ((raid_warnings++))
        fi
        
        # Check cache ratio
        if echo "$hp_cache" | grep -q "Disabled"; then
            warn "Cache appears to be disabled"
            ((raid_warnings++))
        fi
        
        if $REPORT_MODE; then
            echo "" >> "$REPORT_FILE"
            echo "Full HP Smart Array output:" >> "$REPORT_FILE"
            $hpcli ctrl all show config detail >> "$REPORT_FILE" 2>&1
        fi
        
    # Check for Adaptec
    elif command -v arcconf &> /dev/null; then
        found_controller=true
        
        info "Adaptec RAID controller detected"
        
        local adaptec_info=$(arcconf getconfig 1)
        echo "$adaptec_info"
        raid_output+="$adaptec_info\n"
        
        echo ""
        info "Checking battery backup:"
        local adaptec_bbu=$(arcconf getconfig 1 | grep -A 5 -i battery)
        echo "$adaptec_bbu"
        raid_output+="\nBattery:\n$adaptec_bbu\n"
        
        # Check battery status
        if echo "$adaptec_bbu" | grep -qi "optimal\|ok"; then
            log "Battery Status: OK ✓"
        else
            warn "Battery Status: Check output above"
            ((raid_warnings++))
        fi
        
        if $REPORT_MODE; then
            echo "" >> "$REPORT_FILE"
            echo "Full Adaptec output:" >> "$REPORT_FILE"
            arcconf getconfig 1 >> "$REPORT_FILE" 2>&1
        fi
        
    else
        warn "No supported RAID controller tools found"
        warn "Install: megacli/storcli (LSI/Broadcom), ssacli (HP), or arcconf (Adaptec)"
    fi
    
    capture_output "$raid_output"
    
    if ! $found_controller; then
        # Check if any RAID controllers exist in lspci
        local lspci_raid=$(lspci | grep -i raid)
        if [[ -n "$lspci_raid" ]]; then
            info "RAID controller(s) found in system:"
            echo "$lspci_raid"
            capture_output "$lspci_raid"
            warn "Install appropriate management tools for detailed status"
        else
            info "No RAID controllers detected in system"
        fi
        return 1
    fi
    
    # Summary
    echo ""
    if [[ $raid_warnings -eq 0 ]]; then
        log "RAID configuration check: All optimal ✓"
    else
        error "RAID configuration check: $raid_warnings warning(s) found!"
    fi
    
    return $raid_warnings
}

run_all_hardware_checks() {
    log "Running comprehensive hardware verification..."
    echo ""
    
    local total_checks=0
    local failed_checks=0
    
    echo "=========================================="
    ((total_checks++))
    check_network_interfaces || ((failed_checks++))
    
    echo ""
    echo "=========================================="
    ((total_checks++))
    check_nvidia_gpu || ((failed_checks++))
    
    echo ""
    echo "=========================================="
    ((total_checks++))
    check_cpu || ((failed_checks++))
    
    echo ""
    echo "=========================================="
    ((total_checks++))
    check_memory || ((failed_checks++))
    
    echo ""
    echo "=========================================="
    ((total_checks++))
    check_power_supplies || ((failed_checks++))
    
    echo ""
    echo "=========================================="
    ((total_checks++))
    check_raid_controller || ((failed_checks++))
    
    echo ""
    echo "=========================================="
    if [[ $failed_checks -eq 0 ]]; then
        log "All hardware checks completed successfully!"
    else
        warn "$failed_checks out of $total_checks hardware checks had issues"
    fi
    
    return $failed_checks
}

# ============================================
# SECTION 2: Basic System Verification
# ============================================
verify_commands() {
    log "Starting basic system verification..."
    
    local failed=0
    
    # Check if system is Linux
    if [[ "$(uname -s)" != "Linux" ]]; then
        error "This script requires Linux"
        ((failed++))
    else
        log "OS check passed: Linux"
    fi
    
    # Check network connectivity
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log "Network connectivity: OK"
    else
        warn "Network connectivity: FAILED"
        ((failed++))
    fi
    
    # Check disk space (warn if root partition < 10% free)
    local root_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [[ $root_usage -lt 90 ]]; then
        log "Disk space: OK (${root_usage}% used)"
    else
        warn "Disk space: LOW (${root_usage}% used)"
        ((failed++))
    fi
    
    # Check required commands exist
    local required_cmds=("ip" "lsblk" "mount")
    for cmd in "${required_cmds[@]}"; do
        if command -v "$cmd" &> /dev/null; then
            log "Command check: $cmd found"
        else
            error "Command check: $cmd NOT FOUND"
            ((failed++))
        fi
    done
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        log "Permission check: Running as root"
    else
        error "Permission check: Must run as root"
        ((failed++))
    fi
    
    if [[ $failed -gt 0 ]]; then
        error "$failed check(s) failed"
        return 1
    else
        log "All basic verification checks passed!"
        return 0
    fi
}

# ============================================
# SECTION 3: Netplan Configuration
# ============================================
configure_netplan() {
    log "Starting Netplan configuration..."
    
    if ! command -v netplan &> /dev/null; then
        error "netplan not found - is this a system using netplan?"
        return 1
    fi
    
    # Display available interfaces
    log "Available network interfaces:"
    ip -br link show | grep -v lo
    
    echo ""
    read -p "Enter number of interfaces to configure: " num_interfaces
    
    local netplan_config="/etc/netplan/01-netcfg.yaml"
    local backup="/etc/netplan/01-netcfg.yaml.backup.$(date +%s)"
    
    # Backup existing config if it exists
    if [[ -f "$netplan_config" ]]; then
        cp "$netplan_config" "$backup"
        log "Backed up existing netplan config to $backup"
    fi
    
    # Start building the netplan config
    cat > "$netplan_config" << 'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
EOF
    
    # Configure each interface
    for ((i=1; i<=num_interfaces; i++)); do
        echo ""
        read -p "Interface $i name (e.g., eth0, ens33): " iface_name
        read -p "Use DHCP for $iface_name? (y/n): " use_dhcp
        
        cat >> "$netplan_config" << EOF
    $iface_name:
EOF
        
        if [[ "$use_dhcp" =~ ^[Yy]$ ]]; then
            cat >> "$netplan_config" << EOF
      dhcp4: true
EOF
        else
            read -p "Enter static IP (e.g., 192.168.1.100/24): " static_ip
            read -p "Enter gateway IP (e.g., 192.168.1.1): " gateway_ip
            read -p "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers
            
            # Convert comma-separated DNS to array
            IFS=',' read -ra dns_array <<< "$dns_servers"
            
            cat >> "$netplan_config" << EOF
      dhcp4: false
      addresses:
        - $static_ip
      routes:
        - to: default
          via: $gateway_ip
      nameservers:
        addresses:
EOF
            for dns in "${dns_array[@]}"; do
                cat >> "$netplan_config" << EOF
          - $(echo $dns | xargs)
EOF
            done
        fi
    done
    
    log "Generated netplan configuration:"
    cat "$netplan_config"
    
    echo ""
    read -p "Apply this configuration? (y/n): " apply_config
    
    if [[ "$apply_config" =~ ^[Yy]$ ]]; then
        netplan apply
        log "Netplan configuration applied successfully"
    else
        warn "Configuration saved but not applied. Run 'netplan apply' manually."
    fi
}

# ============================================
# SECTION 4: Volume Format and Mount
# ============================================
format_and_mount() {
    log "Starting volume configuration..."
    
    # Display available block devices
    log "Available block devices:"
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
    
    echo ""
    warn "WARNING: Formatting will destroy all data on the selected device!"
    read -p "Enter device to format (e.g., sdb, nvme0n1): " device_name
    
    # Add /dev/ prefix if not present
    if [[ ! "$device_name" =~ ^/dev/ ]]; then
        device_path="/dev/$device_name"
    else
        device_path="$device_name"
    fi
    
    # Verify device exists
    if [[ ! -b "$device_path" ]]; then
        error "Device $device_path does not exist"
        return 1
    fi
    
    # Check if device is mounted
    if mount | grep -q "^$device_path"; then
        error "Device $device_path is currently mounted. Unmount it first."
        return 1
    fi
    
    read -p "Enter filesystem type (ext4/xfs/btrfs) [default: ext4]: " fs_type
    fs_type=${fs_type:-ext4}
    
    read -p "Enter mount point (e.g., /mnt/data): " mount_point
    
    read -p "Enter label for filesystem [optional]: " fs_label
    
    echo ""
    warn "FINAL WARNING: About to format $device_path as $fs_type"
    read -p "Type 'YES' to continue: " confirm
    
    if [[ "$confirm" != "YES" ]]; then
        warn "Operation cancelled"
        return 1
    fi
    
    # Format the device
    log "Formatting $device_path as $fs_type..."
    case "$fs_type" in
        ext4)
            if [[ -n "$fs_label" ]]; then
                mkfs.ext4 -L "$fs_label" "$device_path"
            else
                mkfs.ext4 "$device_path"
            fi
            ;;
        xfs)
            if [[ -n "$fs_label" ]]; then
                mkfs.xfs -L "$fs_label" "$device_path"
            else
                mkfs.xfs "$device_path"
            fi
            ;;
        btrfs)
            if [[ -n "$fs_label" ]]; then
                mkfs.btrfs -L "$fs_label" "$device_path"
            else
                mkfs.btrfs "$device_path"
            fi
            ;;
        *)
            error "Unsupported filesystem type: $fs_type"
            return 1
            ;;
    esac
    
    # Create mount point
    if [[ ! -d "$mount_point" ]]; then
        mkdir -p "$mount_point"
        log "Created mount point: $mount_point"
    fi
    
    # Get UUID
    local uuid=$(blkid -s UUID -o value "$device_path")
    log "Device UUID: $uuid"
    
    # Mount the device
    mount "$device_path" "$mount_point"
    log "Mounted $device_path to $mount_point"
    
    # Backup fstab
    cp /etc/fstab /etc/fstab.backup.$(date +%s)
    
    # Add to fstab
    read -p "Add to /etc/fstab for automatic mounting? (y/n): " add_fstab
    
    if [[ "$add_fstab" =~ ^[Yy]$ ]]; then
        read -p "Enter mount options [default: defaults]: " mount_opts
        mount_opts=${mount_opts:-defaults}
        
        echo "UUID=$uuid $mount_point $fs_type $mount_opts 0 2" >> /etc/fstab
        log "Added entry to /etc/fstab"
        
        # Verify fstab
        if mount -a; then
            log "fstab verification successful"
        else
            error "fstab verification failed - check /etc/fstab"
        fi
    fi
    
    log "Volume configuration complete!"
}

# ============================================
# SECTION 7: Report Generation
# ============================================

initialize_report() {
    local hostname=$(hostname)
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    # Create report directory if it doesn't exist
    mkdir -p "$REPORT_DIR"
    
    REPORT_FILE="$REPORT_DIR/system-config-report_${hostname}_${timestamp}.txt"
    REPORT_MODE=true
    
    # Write report header
    cat > "$REPORT_FILE" << EOF
==========================================
SYSTEM CONFIGURATION REPORT
==========================================
Hostname: $hostname
Date: $(date)
Report Generated By: $(whoami)
==========================================

EOF
    
    log "Report initialized: $REPORT_FILE"
}

finalize_report() {
    if $REPORT_MODE; then
        # Add system information summary at the end
        cat >> "$REPORT_FILE" << EOF

==========================================
ADDITIONAL SYSTEM INFORMATION
==========================================
EOF
        
        echo "" >> "$REPORT_FILE"
        echo "Kernel Version:" >> "$REPORT_FILE"
        uname -a >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "OS Release:" >> "$REPORT_FILE"
        cat /etc/*-release >> "$REPORT_FILE" 2>&1
        
        echo "" >> "$REPORT_FILE"
        echo "Uptime:" >> "$REPORT_FILE"
        uptime >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "Disk Usage:" >> "$REPORT_FILE"
        df -h >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "Block Devices:" >> "$REPORT_FILE"
        lsblk >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "PCI Devices:" >> "$REPORT_FILE"
        lspci >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "USB Devices:" >> "$REPORT_FILE"
        lsusb >> "$REPORT_FILE" 2>&1
        
        echo "" >> "$REPORT_FILE"
        echo "Network Configuration:" >> "$REPORT_FILE"
        ip addr >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "Routing Table:" >> "$REPORT_FILE"
        ip route >> "$REPORT_FILE"
        
        # Add current netplan config if it exists
        if [[ -d /etc/netplan ]]; then
            echo "" >> "$REPORT_FILE"
            echo "Current Netplan Configuration:" >> "$REPORT_FILE"
            for conf in /etc/netplan/*.yaml; do
                if [[ -f "$conf" ]]; then
                    echo "=== $conf ===" >> "$REPORT_FILE"
                    cat "$conf" >> "$REPORT_FILE"
                    echo "" >> "$REPORT_FILE"
                fi
            done
        fi
        
        # Add fstab
        echo "" >> "$REPORT_FILE"
        echo "Current /etc/fstab:" >> "$REPORT_FILE"
        cat /etc/fstab >> "$REPORT_FILE"
        
        cat >> "$REPORT_FILE" << EOF

==========================================
END OF REPORT
==========================================
EOF
        
        log "Report finalized: $REPORT_FILE"
        log "Report size: $(du -h "$REPORT_FILE" | cut -f1)"
        
        # Create a compressed archive
        local archive="${REPORT_FILE%.txt}.tar.gz"
        tar -czf "$archive" -C "$(dirname "$REPORT_FILE")" "$(basename "$REPORT_FILE")"
        
        if [[ -f "$archive" ]]; then
            log "Compressed archive created: $archive"
            log "Archive size: $(du -h "$archive" | cut -f1)"
        fi
        
        REPORT_MODE=false
        
        echo ""
        info "Report and archive available at:"
        info "  Text: $REPORT_FILE"
        info "  Archive: $archive"
    fi
}

generate_full_report() {
    log "Starting full system report generation..."
    echo ""
    
    initialize_report
    
    # Run all hardware checks
    run_all_hardware_checks
    
    # Add system verification
    echo ""
    echo "=========================================="
    report_section "BASIC SYSTEM VERIFICATION"
    verify_commands
    
    finalize_report
    
    echo ""
    log "Full system report generation complete!"
}

# ============================================
# MAIN MENU
# ============================================
main_menu() {
    while true; do
        echo ""
        echo "======================================"
        echo "Linux System Configuration Script"
        echo "======================================"
        echo "Hardware Verification:"
        echo "  1. Check Network Interfaces"
        echo "  2. Check NVIDIA GPU & Drivers"
        echo "  3. Check CPU Info"
        echo "  4. Check Memory Modules"
        echo "  5. Check Power Supplies"
        echo "  6. Check RAID Controller"
        echo "  7. Run ALL Hardware Checks"
        echo ""
        echo "System Configuration:"
        echo "  8. Verify Basic System Commands"
        echo "  9. Configure Netplan"
        echo "  10. Format and Mount Volume"
        echo ""
        echo "Reporting:"
        echo "  11. Generate Full System Report (Archive)"
        echo "  12. View Recent Reports"
        echo ""
        echo "  13. Run Everything"
        echo "  14. Exit"
        echo ""
        read -p "Select an option: " choice
        
        case $choice in
            1) check_network_interfaces ;;
            2) check_nvidia_gpu ;;
            3) check_cpu ;;
            4) check_memory ;;
            5) check_power_supplies ;;
            6) check_raid_controller ;;
            7) run_all_hardware_checks ;;
            8) verify_commands ;;
            9) configure_netplan ;;
            10) format_and_mount ;;
            11) generate_full_report ;;
            12) 
                if [[ -d "$REPORT_DIR" ]]; then
                    log "Recent reports in $REPORT_DIR:"
                    ls -lth "$REPORT_DIR" | head -20
                else
                    warn "No reports found in $REPORT_DIR"
                fi
                ;;
            13)
                read -p "Generate report while running all tasks? (y/n): " gen_report
                if [[ "$gen_report" =~ ^[Yy]$ ]]; then
                    initialize_report
                fi
                
                run_all_hardware_checks
                echo ""
                verify_commands && configure_netplan && format_and_mount
                
                if [[ "$gen_report" =~ ^[Yy]$ ]]; then
                    finalize_report
                fi
                ;;
            14)
                log "Exiting..."
                exit 0
                ;;
            *)
                error "Invalid option"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# Start the script
main_menu