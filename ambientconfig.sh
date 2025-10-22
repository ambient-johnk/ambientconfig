#!/bin/bash

# Linux System Configuration Script
# Functions: Hardware verification, Command checks, Netplan configuration, Volume formatting/mounting
# Validated for: Ubuntu 24.04 LTS Server
#
# Notes:
# - Uses systemd-networkd as default network backend (not NetworkManager)
# - Netplan 1.0+ with networkd renderer
# - Uses 'routes' syntax instead of deprecated 'gateway4'
# - Requires dmidecode for hardware detection
# - networkctl command for network status

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
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        echo "[INFO] $1" >> "$REPORT_FILE"
    fi
}

error() {
    local msg="${RED}[ERROR]${NC} $1"
    echo -e "$msg"
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        echo "[ERROR] $1" >> "$REPORT_FILE"
    fi
}

warn() {
    local msg="${YELLOW}[WARN]${NC} $1"
    echo -e "$msg"
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        echo "[WARN] $1" >> "$REPORT_FILE"
    fi
}

info() {
    local msg="${BLUE}[INFO]${NC} $1"
    echo -e "$msg"
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        echo "[INFO] $1" >> "$REPORT_FILE"
    fi
}

# Function to write section headers to report
report_section() {
    local section="$1"
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        {
            echo ""
            echo "=========================================="
            echo "$section"
            echo "=========================================="
            echo ""
        } >> "$REPORT_FILE"
    fi
}

# Function to capture command output to report
capture_output() {
    local output="$1"
    if [[ "${REPORT_MODE:-false}" == "true" && -n "$output" ]]; then
        echo "$output" >> "$REPORT_FILE"
    fi
}

# ============================================
# SECTION 1: Hardware Verification
# ============================================

check_network_interfaces() {
    report_section "NETWORK INTERFACES CHECK"
    log "Checking network interfaces..."

    # Build interface list (exclude loopback) safely (no grep -v → no set -e pitfall)
    # Get all network interfaces (excluding loopback)
    local interfaces
    interfaces="$(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo"{split($2,a,"@"); print a[1]}')"

    if [[ -z "$interfaces" ]]; then
        warn "No non-loopback network interfaces found."
        echo ""
        info "Quick Overview:"
        ip -br link show | awk '{print}' || true

        echo ""
        info "Default Routes:"
        ip route show | grep default || echo "  No default route configured"

        return 0   # <-- was 'return 1'
    fi

    local iface_count=0
    local up_count=0
    local down_count=0

    echo ""
    info "Found Network Interfaces:"
    echo ""

    while IFS= read -r iface; do
        [[ -z "$iface" ]] && continue

        ((iface_count++))

        # Get interface details (no PCRE)
        local state
        state="$(ip -o link show "$iface" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="state"){print $(i+1); exit}}')"
        [[ -z "$state" ]] && state="UNKNOWN"

        local mac
        mac="$(cat "/sys/class/net/$iface/address" 2>/dev/null || true)"
        [[ -z "$mac" ]] && mac="N/A"

        local speed=""
        local duplex=""
        local driver=""
        local pci_addr=""

        # Speed
        if [[ -f "/sys/class/net/$iface/speed" ]]; then
            local speed_raw
            speed_raw="$(cat "/sys/class/net/$iface/speed" 2>/dev/null || true)"
            if [[ "$speed_raw" =~ ^-?[0-9]+$ && "$speed_raw" -gt 0 ]]; then
                speed="${speed_raw}Mbps"
            elif [[ "$speed_raw" == "-1" ]]; then
                speed="Unknown"
            else
                speed="N/A"
            fi
        else
            speed="N/A"
        fi

        # Duplex
        if [[ -f "/sys/class/net/$iface/duplex" ]]; then
            duplex="$(cat "/sys/class/net/$iface/duplex" 2>/dev/null || true)"
            [[ -z "$duplex" ]] && duplex="N/A"
        else
            duplex="N/A"
        fi

        # Driver/PCI
        if [[ -L "/sys/class/net/$iface/device" ]]; then
            pci_addr="$(basename "$(readlink "/sys/class/net/$iface/device")" 2>/dev/null || echo "N/A")"
            if [[ -L "/sys/class/net/$iface/device/driver" ]]; then
                driver="$(basename "$(readlink "/sys/class/net/$iface/device/driver")" 2>/dev/null || echo "Unknown")"
            else
                driver="Unknown"
            fi
        else
            driver="Virtual"
            pci_addr="N/A"
        fi

        # IPs (no PCRE)
        local ipv4 ipv6
        ipv4="$(ip -4 -o addr show "$iface" 2>/dev/null | awk '$3=="inet"{print $4; exit}')"
        ipv6="$(ip -6 -o addr show "$iface" 2>/dev/null | awk '$3=="inet6" && $4 !~ /^fe80/{print $4; exit}')"

        # Count up/down
        if [[ "$state" == "UP" ]]; then
            ((up_count++))
            log "[$iface_count] $iface: $state"
        else
            ((down_count++))
            warn "[$iface_count] $iface: $state"
        fi

        echo "  $iface"
        echo "    State:     $state"
        echo "    MAC:       $mac"
        echo "    Driver:    $driver"
        if [[ "$pci_addr" != "N/A" ]]; then
            echo "    PCI:       $pci_addr"
        fi
        if [[ "$state" == "UP" ]]; then
            echo "    Speed:     $speed"
            echo "    Duplex:    $duplex"
        fi
        if [[ -n "$ipv4" ]]; then
            echo "    IPv4:      $ipv4"
        fi
        if [[ -n "$ipv6" ]]; then
            echo "    IPv6:      $ipv6"
        fi
        echo ""

        # Capture to report
        if [[ "${REPORT_MODE:-false}" == "true" ]]; then
            {
                echo "Interface: $iface"
                echo "  State: $state"
                echo "  MAC: $mac"
                echo "  Driver: $driver"
                [[ "$pci_addr" != "N/A" ]] && echo "  PCI: $pci_addr"
                [[ "$state" == "UP" ]] && echo "  Speed: $speed"
                [[ "$state" == "UP" ]] && echo "  Duplex: $duplex"
                [[ -n "$ipv4" ]] && echo "  IPv4: $ipv4"
                [[ -n "$ipv6" ]] && echo "  IPv6: $ipv6"
                echo ""
            } >> "$REPORT_FILE"
        fi
    done <<< "$interfaces"

    # Summary
    info "Summary: $iface_count interface(s) found - $up_count UP, $down_count DOWN"

    # Quick Overview (avoid grep -v failure under set -e)
    echo ""
    info "Quick Overview:"
    ip -br link show | awk '$1 != "lo" {print}'

    # Show routing table
    echo ""
    info "Default Routes:"
    ip route show | grep default || echo "  No default route configured"

    return 0
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
        local gpu_output
        gpu_output="$(nvidia-smi --query-gpu=index,name,driver_version,memory.total,temperature.gpu,power.draw --format=csv,noheader)"
        echo "$gpu_output" | while IFS=, read -r idx name driver mem temp power; do
            info "GPU $idx: $name"
            info "  Driver: $driver"
            info "  Memory: $mem"
            info "  Temp: $temp"
            info "  Power: $power"
        done
        capture_output "$gpu_output"

        if [[ "${REPORT_MODE:-false}" == "true" ]]; then
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

    local cpu_model cpu_cores cpu_threads cores_per_socket sockets cpu_mhz cpu_max_mhz
    cpu_model="$(lscpu | grep "Model name" | cut -d: -f2 | xargs)"
    cpu_cores="$(lscpu | grep "^CPU(s):" | cut -d: -f2 | xargs)"
    cpu_threads="$(lscpu | grep "^Thread(s) per core:" | cut -d: -f2 | xargs)"
    cores_per_socket="$(lscpu | grep "Core(s) per socket:" | cut -d: -f2 | xargs)"
    sockets="$(lscpu | grep "Socket(s):" | cut -d: -f2 | xargs)"
    cpu_mhz="$(lscpu | grep "CPU MHz:" | cut -d: -f2 | xargs)"
    cpu_max_mhz="$(lscpu | grep "CPU max MHz:" | cut -d: -f2 | xargs)"

    info "CPU Model: $cpu_model"
    info "Total Logical CPUs: $cpu_cores"
    info "Sockets: $sockets"
    info "Cores per Socket: $cores_per_socket"
    info "Threads per Core: $cpu_threads"
    info "Current Speed: ${cpu_mhz} MHz"
    if [[ -n "$cpu_max_mhz" ]]; then
        info "Max Speed: ${cpu_max_mhz} MHz"
    fi

    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        echo "" >> "$REPORT_FILE"
        echo "Full lscpu output:" >> "$REPORT_FILE"
        lscpu >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    info "Per-core current frequencies:"
    local freq_output=""
    for cpu in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
        if [[ -f "$cpu" ]]; then
            local core freq freq_mhz
            core="${cpu%/cpufreq/scaling_cur_freq}"  # .../cpu7
            core="${core##*/}"                       # cpu7
            core="${core#cpu}"                       # 7
            freq="$(cat "$cpu")"
            freq_mhz=$((freq / 1000))
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
        if [[ "${REPORT_MODE:-false}" == "true" ]]; then
            free -h >> "$REPORT_FILE"
        fi
        return 1
    fi

    local total_mem
    total_mem="$(free -h | awk '/^Mem:/ {print $2}')"
    info "Total System Memory: $total_mem"
    echo ""

    info "Installed memory modules:"
    # Collect only populated memory modules (skip "No Module Installed")
    local mem_output
    mem_output="$(dmidecode -t memory | awk '
        /^Memory Device$/ {block=""; skip=0}
        /^$/ {if (block != "" && skip==0) print block; block=""; next}
        /No Module Installed/ {skip=1}
        /Size:|Speed:|Type:|Locator:|Manufacturer:|Serial Number:|Part Number:/ {
            block = block $0 "\n"
        }
        END {if (block != "" && skip==0) print block}
    ')"

    if [[ -n "$mem_output" ]]; then
        echo "$mem_output"
    else
        warn "No populated memory modules detected!"
    fi

    # Capture to report (only populated modules)
    if [[ "${REPORT_MODE:-false}" == "true" && -n "$mem_output" ]]; then
        echo "$mem_output" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "Full dmidecode memory output:" >> "$REPORT_FILE"
        dmidecode -t memory >> "$REPORT_FILE" 2>&1
    fi

    # Summary: count populated vs total
    local slot_count populated
    slot_count="$(dmidecode -t memory | grep -c "Memory Device" || true)"
    populated="$(echo "$mem_output" | grep -c "Size:" || true)"
    echo ""
    info "Memory slots: $populated populated out of $slot_count total"
    info "Total System Memory: $total_mem"
    echo ""
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
        local dmi_output
        dmi_output="$(dmidecode --type 39 2>/dev/null || true)"

        if [[ -n "$dmi_output" ]] && ! echo "$dmi_output" | grep -q "No SMBIOS nor DMI entry point found"; then
            # Parse and display PSU information (avoid subshell)
            while IFS= read -r line; do
                if echo "$line" | grep -qE "Location:|Name:|Manufacturer:|Serial Number:|Asset Tag:|Model Part Number:|Max Power Capacity:|Status:|Type:|Input Voltage Range Switching:"; then
                    echo "$line"
                    psu_info+="$line"$'\n'
                    found_psu=true
                fi
            done < <(echo "$dmi_output" | grep -A 15 "System Power Supply" || true)

            if [[ "${REPORT_MODE:-false}" == "true" ]]; then
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
                local name dir
                name="$(cat "$hwmon")"
                dir="$(dirname "$hwmon")"

                for power in "$dir"/power*_input; do
                    if [[ -f "$power" ]]; then
                        local watts
                        watts="$(cat "$power")"
                        watts=$((watts / 1000000))
                        local label_file="${power/input/label}"
                        local label="unknown"
                        if [[ -f "$label_file" ]]; then
                            label="$(cat "$label_file")"
                        fi
                        info "  $name - $label: ${watts}W"
                        psu_info+="$name - $label: ${watts}W"$'\n'
                        found_hwmon=true
                    fi
                done
            fi
        done
        if [[ "$found_hwmon" != true ]]; then
            info "  No power sensors found in sysfs"
        fi
    fi

    capture_output "$psu_info"

    # No interactive expected-wattage prompt anymore
    # Optionally warn if we didn't find any PSU info at all
    if [[ "$found_psu" != true ]]; then
        warn "No PSU details were discovered via SMBIOS; consider checking BMC/iDRAC/iLO or chassis labels."
    fi

    return 0
}


check_raid_controller() {
    report_section "RAID CONTROLLER INFORMATION"
    log "Checking RAID controller configuration (perccli64)..."

    local PERC="/opt/MegaRAID/perccli/perccli64"

    if [[ ! -x "$PERC" ]]; then
        error "perccli64 not found or not executable at $PERC"
        warn "Install/verify MegaRAID PERC CLI (perccli64) and path."
        return 1
    fi

    local raid_output=""
    local raid_warnings=0

    # -------- Controller summary --------
    info "Controller summary (/c0 show all):"
    local ctrl_all
    ctrl_all="$("$PERC" /c0 show all 2>/dev/null || true)"
    if [[ -z "$ctrl_all" ]]; then
        error "perccli64 returned no data for /c0 show all"
        return 1
    fi
    echo "$ctrl_all"
    raid_output+="$ctrl_all"$'\n'

    # Extract some basics (best-effort; layout varies by version)
    local prod_name fw_ver roc_temp
    prod_name="$(echo "$ctrl_all" | awk -F':' '/Product Name/ {gsub(/^[ \t]+/,"",$2); print $2; exit}')"
    fw_ver="$(echo "$ctrl_all"   | awk -F':' '/FW Version/   {gsub(/^[ \t]+/,"",$2); print $2; exit}')"
    roc_temp="$(echo "$ctrl_all" | awk -F':' '/ROC temperature/ {gsub(/^[ \t]+/,"",$2); print $2; exit}')"

    [[ -n "$prod_name" ]] && info "  Product: $prod_name"
    [[ -n "$fw_ver"   ]] && info "  FW: $fw_ver"
    [[ -n "$roc_temp" ]] && info "  ROC Temp: $roc_temp"

    # -------- Battery / CacheVault status --------
    echo ""
    info "Checking BBU/CacheVault status..."
    # Try CV first (newer controllers), fallback to BBU
    local bbu_cv_info
    bbu_cv_info="$("$PERC" /c0/cv show all 2>/dev/null || "$PERC" /c0/bbu show all 2>/dev/null || true)"
    if [[ -n "$bbu_cv_info" ]]; then
        echo "$bbu_cv_info"
        raid_output+=$'\n'"BBU/CV Status:"$'\n'"$bbu_cv_info"$'\n'
        # Determine state (look for 'Optimal' first)
        if echo "$bbu_cv_info" | grep -qi "Optimal"; then
            log "BBU/CV Status: Optimal ✓"
        else
            local bstate
            bstate="$(echo "$bbu_cv_info" | awk -F':' 'tolower($0) ~ /state/ {gsub(/^[ \t]+/,"",$2); print $2; exit}')"
            error "BBU/CV Status: ${bstate:-Unknown} - NOT OPTIMAL!"
            ((raid_warnings++))
        fi
    else
        warn "No BBU/CV information available from perccli64"
        ((raid_warnings++))
    fi

    # -------- Virtual drive states & cache policy --------
    echo ""
    info "Checking Virtual Drive states and cache policies..."
    local vd_all
    vd_all="$("$PERC" /c0/vall show all 2>/dev/null || true)"
    if [[ -z "$vd_all" ]]; then
        warn "No virtual drive information available from perccli64"
        ((raid_warnings++))
    else
        # Print a concise subset (State/Cache lines)
        echo "$vd_all" | grep -Ei "^(VD|DG)|State|Cache" || true
        raid_output+=$'\n'"VD All:"$'\n'"$vd_all"$'\n'

        # Parse each VD block for State and Cache policy
        # VD headers often look like: "VD0 Properties", "Virtual Drive: 0", or "VD number: 0"
        # We'll infer VD indices by scanning "Virtual Drive:" or "VD[[:space:]]*:" markers.
        local vd_index state_line cache_line
        # Normalize lines to simplify parsing
        while IFS= read -r line; do
            # Capture VD index
            if echo "$line" | grep -Eq 'Virtual Drive[:[:space:]]+([0-9]+)|^VD[[:space:]]*([0-9]+)'; then
                # Print previous VD analysis (if any)
                if [[ -n "$vd_index" ]]; then
                    # Evaluate prior VD gathered fields
                    local vd_state="${state_line#*: }"
                    local vd_cache="${cache_line#*: }"
                    if [[ -n "$vd_state" ]]; then
                        if [[ "$vd_state" =~ ^[Oo]ptimal$ ]]; then
                            log "  VD $vd_index: State=Optimal ✓"
                        else
                            error "  VD $vd_index: State=${vd_state:-Unknown} - NOT OPTIMAL!"
                            ((raid_warnings++))
                        fi
                    fi
                    if [[ -n "$vd_cache" ]]; then
                        # Heuristics:
                        # Prefer WriteBack + ReadAhead (often listed as WB / RA / Cached / etc.)
                        # Treat RWBD/WriteBack NR or WriteThrough as warnings.
                        if echo "$vd_cache" | grep -qi "WriteThrough\|WT\b"; then
                            warn "  VD $vd_index: Cache=WriteThrough - performance impact"
                            ((raid_warnings++))
                        elif echo "$vd_cache" | grep -qi "NR\b"; then
                            warn "  VD $vd_index: Cache=WriteBack NR (battery dependent) - EXCEPTION"
                            ((raid_warnings++))
                        else
                            log  "  VD $vd_index: Cache=$vd_cache ✓"
                        fi
                    fi
                fi
                # Reset for new VD
                vd_index="$(echo "$line" | sed -nE 's/.*Virtual Drive[:[:space:]]+([0-9]+).*/\1/p;s/^VD[[:space:]]*([0-9]+).*/\1/p' | head -1)"
                state_line=""
                cache_line=""
                continue
            fi

            # Capture key lines
            if [[ -z "$state_line" ]] && echo "$line" | grep -Eq '^[[:space:]]*State[[:space:]]*:'; then
                state_line="$(echo "$line" | sed -E 's/^[[:space:]]*//')"
            fi
            if [[ -z "$cache_line" ]] && echo "$line" | grep -Eq '^[[:space:]]*Cache[[:space:]]*:'; then
                cache_line="$(echo "$line" | sed -E 's/^[[:space:]]*//')"
            fi
        done < <(printf '%s\n' "$vd_all")

        # Flush last VD parsed (if any)
        if [[ -n "$vd_index" ]]; then
            local vd_state="${state_line#*: }"
            local vd_cache="${cache_line#*: }"
            if [[ -n "$vd_state" ]]; then
                if [[ "$vd_state" =~ ^[Oo]ptimal$ ]]; then
                    log "  VD $vd_index: State=Optimal ✓"
                else
                    error "  VD $vd_index: State=${vd_state:-Unknown} - NOT OPTIMAL!"
                    ((raid_warnings++))
                fi
            fi
            if [[ -n "$vd_cache" ]]; then
                if echo "$vd_cache" | grep -qi "WriteThrough\|WT\b"; then
                    warn "  VD $vd_index: Cache=WriteThrough - performance impact"
                    ((raid_warnings++))
                elif echo "$vd_cache" | grep -qi "NR\b"; then
                    warn "  VD $vd_index: Cache=WriteBack NR (battery dependent) - EXCEPTION"
                    ((raid_warnings++))
                else
                    log  "  VD $vd_index: Cache=$vd_cache ✓"
                fi
            fi
        fi
    fi

    # -------- Summary & reporting --------
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        {
            echo ""
            echo "perccli64 summary (/c0 show all):"
            echo "$ctrl_all"
            echo ""
            echo "BBU/CV:"
            echo "$bbu_cv_info"
            echo ""
            echo "VD details:"
            echo "$vd_all"
        } >> "$REPORT_FILE"
    fi

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

    # Check Ubuntu version
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        info "Distribution: $NAME $VERSION"

        if [[ "$ID" == "ubuntu" ]]; then
            local version_number
            version_number="$(echo "$VERSION_ID" | cut -d. -f1)"
            if [[ $version_number -ge 24 ]]; then
                log "Ubuntu 24.04 or newer detected ✓"

                if systemctl is-enabled systemd-networkd &> /dev/null; then
                    log "systemd-networkd is enabled (Ubuntu 24.04 default) ✓"
                else
                    warn "systemd-networkd is not enabled - may need configuration"
                fi
            fi
        fi
    fi

    # Check network connectivity
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log "Network connectivity: OK"
    else
        warn "Network connectivity: FAILED"
        ((failed++))
    fi

    # Check disk space (warn if root partition < 10% free)
    local root_usage
    root_usage="$(df / | tail -1 | awk '{print $5}' | sed 's/%//')"
    if [[ $root_usage -lt 90 ]]; then
        log "Disk space: OK (${root_usage}% used)"
    else
        warn "Disk space: LOW (${root_usage}% used)"
        ((failed++))
    fi

    # Check required commands exist
    local required_cmds=("ip" "lsblk" "mount" "lscpu" "dmidecode")
    local optional_cmds=("netplan" "networkctl")

    for cmd in "${required_cmds[@]}"; do
        if command -v "$cmd" &> /dev/null; then
            log "Command check: $cmd found"
        else
            error "Command check: $cmd NOT FOUND"
            ((failed++))
        fi
    done

    for cmd in "${optional_cmds[@]}"; do
        if command -v "$cmd" &> /dev/null; then
            log "Optional command: $cmd found"
        else
            info "Optional command: $cmd not found (may need installation)"
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

    # Check systemd-networkd is available (Ubuntu 24.04 Server default)
    if ! systemctl is-enabled systemd-networkd &> /dev/null; then
        warn "systemd-networkd is not enabled. Enabling it now..."
        systemctl enable systemd-networkd
    fi

    # Display available interfaces
    log "Available network interfaces:"
    ip -br link show | awk '$1 != "lo" {print}'

    echo ""
    read -p "Enter number of interfaces to configure: " num_interfaces

    local netplan_config="/etc/netplan/01-netcfg.yaml"
    local backup="/etc/netplan/01-netcfg.yaml.backup.$(date +%s)"

    # Backup existing config if it exists
    if [[ -f "$netplan_config" ]]; then
        cp "$netplan_config" "$backup"
        log "Backed up existing netplan config to $backup"
    fi

    # Start building the netplan config (Ubuntu 24.04 uses networkd renderer)
    cat > "$netplan_config" << 'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
EOF

    # Configure each interface
    for ((i=1; i<=num_interfaces; i++)); do
        echo ""
        read -p "Interface $i name (e.g., eth0, ens33, enp0s31f6): " iface_name
        read -p "Use DHCP for $iface_name? (y/n): " use_dhcp

        cat >> "$netplan_config" << EOF
    $iface_name:
EOF

        if [[ "$use_dhcp" =~ ^[Yy]$ ]]; then
            cat >> "$netplan_config" << EOF
      dhcp4: true
      dhcp6: true
EOF
        else
            read -p "Enter static IP (e.g., 192.168.1.100/24): " static_ip
            read -p "Enter gateway IP (e.g., 192.168.1.1): " gateway_ip
            read -p "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers

            IFS=',' read -ra dns_array <<< "$dns_servers"

            cat >> "$netplan_config" << EOF
      dhcp4: false
      dhcp6: false
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
          - $(echo "$dns" | xargs)
EOF
            done
        fi
    done

    log "Generated netplan configuration:"
    cat "$netplan_config"

    echo ""
    info "Validating netplan configuration..."
    if netplan generate; then
        log "Netplan configuration is valid ✓"
    else
        error "Netplan configuration has errors!"
        return 1
    fi

    echo ""
    read -p "Apply this configuration? (y/n): " apply_config

    if [[ "$apply_config" =~ ^[Yy]$ ]]; then
        log "Applying netplan configuration..."
        netplan apply

        sleep 2

        if systemctl is-active systemd-networkd &> /dev/null; then
            log "systemd-networkd is running ✓"
        else
            warn "systemd-networkd is not running - restarting..."
            systemctl restart systemd-networkd
        fi

        echo ""
        log "Network interface status:"
        networkctl status

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
    local device_path
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
    local uuid
    uuid="$(blkid -s UUID -o value "$device_path")"
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
    local hostname timestamp
    hostname="$(hostname)"
    timestamp="$(date +"%Y%m%d_%H%M%S")"

    mkdir -p "$REPORT_DIR"

    REPORT_FILE="$REPORT_DIR/system-config-report_${hostname}_${timestamp}.txt"
    REPORT_MODE=true

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
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        cat >> "$REPORT_FILE" << EOF

==========================================
ADDITIONAL SYSTEM INFORMATION
==========================================
EOF

        {
            echo ""
            echo "Kernel Version:"
            uname -a

            echo ""
            echo "OS Release:"
            cat /etc/*-release 2>&1

            echo ""
            echo "Uptime:"
            uptime

            echo ""
            echo "Disk Usage:"
            df -h

            echo ""
            echo "Block Devices:"
            lsblk

            echo ""
            echo "PCI Devices:"
            lspci

            echo ""
            echo "USB Devices:"
            lsusb 2>&1

            echo ""
            echo "Network Configuration:"
            ip addr

            echo ""
            echo "Routing Table:"
            ip route
        } >> "$REPORT_FILE"

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

        local archive
        archive="${REPORT_FILE%.txt}.tar.gz"
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

    run_all_hardware_checks

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
        echo "Linux System Configuration Script v0.2"
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
