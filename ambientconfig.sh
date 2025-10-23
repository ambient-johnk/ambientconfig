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
    local interfaces
    # Exclude lo, docker*, veth*
    interfaces="$(ip -o link show 2>/dev/null \
    | awk -F': ' '{
        split($2,a,"@"); name=a[1];
        if (name!="lo" && name!="" && name !~ /^(veth|docker)/) print name
        }')"

    if [[ -z "$interfaces" ]]; then
        warn "No non-loopback network interfaces found."
        echo ""
        info "Quick Overview:"
        ip -br link show | awk '$1!="lo" && $1 !~ /^(veth|docker)/ {print}' || true

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
    ip -br link show | awk '$1!="lo" && $1 !~ /^(veth|docker)/ {print}' || true

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
    cpu_mhz="$(lscpu | awk -F: '/CPU MHz/{gsub(/[ \t]/,"",$2); print $2; exit}')"
    cpu_max_mhz="$(lscpu | awk -F: '/CPU max MHz/{gsub(/[ \t]/,"",$2); print $2; exit}')"

    # Fallback for current speed if lscpu didn't provide it
    if [[ -z "$cpu_mhz" ]]; then
        # Average of per-core “cpu MHz” from /proc/cpuinfo
        local avg
        avg="$(awk -F: '/^cpu MHz/ {gsub(/[ \t]/,"",$2); sum+=$2; n++} END{if(n) printf "%.0f", sum/n}' /proc/cpuinfo || true)"
        if [[ -n "$avg" ]]; then
            cpu_mhz="$avg"
        fi
    fi

    info "CPU Model: $cpu_model"
    info "Total Logical CPUs: $cpu_cores"
    info "Sockets: $sockets"
    info "Cores per Socket: $cores_per_socket"
    info "Threads per Core: $cpu_threads"
    if [[ -n "$cpu_mhz" ]]; then
        info "Current Speed: ${cpu_mhz} MHz"
    else
        warn "Current Speed: unavailable (no CPU MHz from lscpu or /proc/cpuinfo)"
    fi
    if [[ -n "$cpu_max_mhz" ]]; then
        info "Max Speed: ${cpu_max_mhz} MHz"
    fi

    # Capture full lscpu output to report (optional)
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        echo "" >> "$REPORT_FILE"
        echo "Full lscpu output:" >> "$REPORT_FILE"
        lscpu >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi

    # -------- Per-core current frequencies --------
    info "Per-core current frequencies:"

    # Prefer sysfs cpufreq if present; otherwise fall back to /proc/cpuinfo
    if compgen -G "/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq" > /dev/null; then
        # sysfs path exists
        local freq_output=""
        local f
        for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
            if [[ -f "$f" ]]; then
                local core freq_khz mhz
                core="${f%/cpufreq/scaling_cur_freq}"   # .../cpu7
                core="${core##*/}"                      # cpu7
                core="${core#cpu}"                      # 7
                freq_khz="$(cat "$f" 2>/dev/null || true)"
                if [[ "$freq_khz" =~ ^[0-9]+$ ]]; then
                    mhz=$(( freq_khz / 1000 ))
                    echo "  CPU${core}: ${mhz} MHz"
                    freq_output+="CPU${core}: ${mhz} MHz\n"
                else
                    echo "  CPU${core}: n/a"
                    freq_output+="CPU${core}: n/a\n"
                fi
            fi
        done
        capture_output "$freq_output"
    else
        # Fallback: /proc/cpuinfo per-core
        # Some systems list logical CPUs as "processor : N" with "cpu MHz : XXX"
        awk -F: '
            /^processor[ \t]*:/ { cpu=$2; gsub(/[ \t]/,"",cpu); next }
            /^cpu MHz[ \t]*:/   { mhz=$2; gsub(/^[ \t]+|[ \t]+$/,"",mhz);
                                  printf "  CPU%s: %s MHz\n", cpu, mhz }
        ' /proc/cpuinfo || true
    fi

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
    populated="$(echo "$mem_output" | grep -c -E '^[[:space:]]*Size:' || true)"

    # Calculate total installed size from populated DIMMs
    local total_installed_mb=0
    while IFS= read -r size_line; do
        # Trim leading spaces and parse: "Size: <num> <UNIT>"
        size_line="$(echo "$size_line" | sed -E 's/^[[:space:]]+//')"
        # Skip any non-populated oddities just in case
        if echo "$size_line" | grep -q "No Module Installed"; then
            continue
        fi
        # Extract "num" and "UNIT"
        # Works for: "Size: 16384 MB", "Size: 16 GB", etc.
        if [[ "$size_line" =~ ^Size:\ +([0-9]+)\ +([KkMmGgTt][Bb]) ]]; then
            value="${BASH_REMATCH[1]}"
            unit="${BASH_REMATCH[2]}"
            # Normalize unit
            unit="$(echo "$unit" | tr '[:lower:]' '[:upper:]')"
            case "$unit" in
                KB) (( total_installed_mb += value / 1024 ));;
                MB) (( total_installed_mb += value ));;
                GB) (( total_installed_mb += value * 1024 ));;
                TB) (( total_installed_mb += value * 1024 * 1024 ));;
            esac
        fi
    done < <(echo "$mem_output" | grep -E '^[[:space:]]*Size:')

    # Human-readable totals
    local total_gb=$(( total_installed_mb / 1024 ))
    if (( total_gb >= 1024 )); then
        local total_tb=$(( total_gb / 1024 ))
        info "Total Installed Memory: ${total_tb} TB (${total_gb} GB)"
    elif (( total_gb > 0 )); then
        info "Total Installed Memory: ${total_gb} GB"
    else
        warn "Total Installed Memory could not be parsed from module sizes (reported total: $total_mem)"
    fi
    info "Total System Memory (reported): $total_mem"
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

    # System identity (vendor, model, Service Tag / serial, BIOS, BMC)
    if command -v dmidecode >/dev/null 2>&1; then
        local vendor model service_tag bios_version bios_date bmc_firmware

        vendor="$(dmidecode -s system-manufacturer 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        model="$(dmidecode -s system-product-name 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        service_tag="$(dmidecode -s system-serial-number 2>/dev/null | tr -d '[:space:]')"
        bios_version="$(dmidecode -s bios-version 2>/dev/null | xargs)"
        bios_date="$(dmidecode -s bios-release-date 2>/dev/null | xargs)"
        bmc_firmware="$(ipmitool mc info 2>/dev/null | awk -F: '/Firmware Revision/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' || true)"

        [[ -z "$vendor" || "$vendor" == "None" || "$vendor" == "To Be Filled By O.E.M." ]] && vendor="Unknown vendor"
        [[ -z "$model"  || "$model"  == "None"  || "$model"  == "To Be Filled By O.E.M." ]] && model="Unknown model"

        if [[ -n "$service_tag" && "$service_tag" != "None" && "$service_tag" != "ToBeFilledByO.E.M." ]]; then
            log "System: $vendor $model (Service Tag: $service_tag)"
        else
            log "System: $vendor $model"
            warn "System serial number unavailable or generic."
        fi

        if [[ -n "$bios_version" ]]; then
            log "BIOS Version: $bios_version (${bios_date:-unknown date})"
        fi

        if [[ -n "$bmc_firmware" ]]; then
            log "BMC/iDRAC Firmware Revision: $bmc_firmware"
        fi

        if [[ "${REPORT_MODE:-false}" == "true" ]]; then
            {
                echo "System Identity:"
                echo "  Vendor: $vendor"
                echo "  Model:  $model"
                echo "  Service Tag: ${service_tag:-Unknown}"
                echo "  BIOS Version: ${bios_version:-Unknown} (${bios_date:-N/A})"
                echo "  BMC/iDRAC Firmware: ${bmc_firmware:-N/A}"
                echo ""
            } >> "$REPORT_FILE"
        fi
    else
        warn "dmidecode not found; cannot retrieve system identity / Service Tag / BIOS info"
    fi


    # Check network connectivity
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log "Ping 8.8.8.8 Network connectivity: OK"
    else
        warn "Ping 8.8.8.8 Network connectivity: FAILED"
        ((failed++))
    fi

    # DNS resolution checks (IPv4 only)
    info "Checking DNS resolution (IPv4 only)..."
    local dns_failed=0
    local domains=("api.ambient.ai" "app.ambient.ai" "www.google.com")

    for domain in "${domains[@]}"; do
        # getent ahostsv4 prints IPv4 results only; pick first dotted-quad
        local raw ipv4
        raw="$(getent ahostsv4 "$domain" 2>/dev/null || true)"
        ipv4="$(printf '%s\n' "$raw" | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1; exit}')"

        if [[ -n "$ipv4" ]]; then
            log "DNS A for $domain: $ipv4 ✓"
        else
            warn "DNS lookup (A) for $domain failed or returned no IPv4!"
            if [[ -n "$raw" ]]; then
                local first_line
                first_line="$(printf '%s\n' "$raw" | head -1)"
                [[ -n "$first_line" ]] && info "Resolver returned (first line): $first_line"
            fi
            ((dns_failed++))
        fi
    done

    if (( dns_failed > 0 )); then
        warn "$dns_failed DNS check(s) failed — verify A records or resolver settings."
        ((failed++))
    fi


    # HTTPS reachability checks
    info "Checking HTTPS connectivity..."
    local https_failed=0

    if command -v curl >/dev/null 2>&1; then
        # Use HEAD (-I); treat any non-000 code as reachable (000 = network/DNS/TLS error)
        for url in "https://app.ambient.ai/" "https://checkip.amazonaws.com/"; do
            local code
            if [[ "$url" == "https://checkip.amazonaws.com/" ]]; then
                code="$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "$url" || true)"
            else
                code="$(curl -sS -o /dev/null -w "%{http_code}" -I --connect-timeout 5 --max-time 8 "$url" || true)"
            fi
            if [[ -n "$code" && "$code" != "000" ]]; then
                log "HTTPS OK: $url (HTTP $code) ✓"
            else
                warn "HTTPS to $url failed (timeout/TLS/DNS error)"
                ((https_failed++))
            fi
        done
    else
        warn "curl not found; skipping HTTPS connectivity checks"
        # Optional: mark as a soft failure
        # ((failed++))
    fi

    if (( https_failed > 0 )); then
        warn "$https_failed HTTPS check(s) failed"
        ((failed++))
    fi

    # Public IP address check
    info "Checking public IP address..."
    if command -v curl >/dev/null 2>&1; then
        local pub_ip
        pub_ip="$(curl -s --max-time 5 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
        if [[ -n "$pub_ip" ]]; then
            log "Public IP address: $pub_ip"
        else
            warn "Unable to retrieve public IP from checkip.amazonaws.com"
            ((failed++))
        fi
    else
        warn "curl not found; skipping public IP check"
        ((failed++))
    fi

    # Check disk space (warn if root partition < 10% free)
    local root_usage
    root_usage="$(df / | tail -1 | awk '{print $5}' | sed 's/%//')"
    if [[ $root_usage -lt 90 ]]; then
        log "Boot/Root Disk space: OK (${root_usage}% used)"
    else
        warn "Boot/Root Disk space: LOW (${root_usage}% used)"
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

    # Warn if cloud-init networking may override our changes
    if grep -qs "network:" /etc/cloud/cloud.cfg 2>/dev/null || \
       compgen -G "/etc/cloud/cloud.cfg.d/*.cfg" >/dev/null; then
        if ! grep -qs "network: {config: disabled}" /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg 2>/dev/null; then
            warn "cloud-init networking may override netplan. To disable it:"
            info "  echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"
            info "  Then re-run this step."
        fi
    fi

    # Check systemd-networkd is available (Ubuntu 24.04 Server default)
    if ! systemctl is-enabled systemd-networkd &> /dev/null; then
        warn "systemd-networkd is not enabled. Enabling it now..."
        systemctl enable systemd-networkd
    fi

    # Display available interfaces
    log "Available network interfaces:"
#    ip -br link show | awk '$1 != "lo" {print}'
    ip -br link show | awk '$1!="lo" && $1 !~ /^(veth|docker)/ {print}' || true

    echo ""
    read -p "Enter number of interfaces to configure: " num_interfaces

    local netplan_config="/etc/netplan/50-cloud-init.yaml"
    local backup="/etc/netplan/50-cloud-init.yaml.backup.$(date +%s)"

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
EOF
        else
            read -p "Enter static IP (e.g., 192.168.1.100/24): " static_ip
            read -p "Enter gateway IP (e.g., 192.168.1.1): " gateway_ip
            read -p "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers

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
    read -p "Apply this configuration? If no, it is saved, apply it later (y/n): " apply_config

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

    # Show inventory
    info "Block devices and partitions:"
    lsblk -o NAME,MODEL,SIZE,TYPE,FSTYPE,MOUNTPOINT | sed 's/^/  /'

    # Collect mounted device paths
    local mounted_list
    mounted_list="$(lsblk -nrpo NAME,MOUNTPOINT | awk '$2!=""{print $1}' | sort -u)"

    echo ""
    warn "Safety: do NOT select a mounted device/partition."
    echo "Type 'q' or 'quit' at any time to return to the main menu."
    read -p "Enter target device or partition (e.g., /dev/sda or /dev/sdb1): " target

    # Allow quitting
    case "$target" in
        q|Q|quit|QUIT)
            warn "Operation cancelled. Returning to main menu..."
            return 0
            ;;
    esac

    # Normalize to /dev/*
    if [[ -n "$target" && "$target" != /dev/* ]]; then
        target="/dev/$target"
    fi

    # Validate target
    if [[ ! -b "$target" ]]; then
        error "Block device $target not found."
        return 1
    fi

    # Refuse if mounted
    if echo "$mounted_list" | grep -qx "$target"; then
        error "$target is currently mounted. Unmount it first, then retry."
        return 1
    fi

    # Check for existing filesystem
    local cur_fs
    cur_fs="$(blkid -o value -s TYPE "$target" 2>/dev/null || true)"
    if [[ -n "$cur_fs" ]]; then
        info "$target already has a filesystem: $cur_fs"
        read -p "Skip formatting and just mount it? (y/N): " skip_fmt
        if [[ "$skip_fmt" =~ ^[Yy]$ ]]; then
            :
        else
            warn "Reformatting WILL DESTROY ALL DATA on $target!"
            read -p "Type 'YES' to confirm reformat as ext4 (label 'data'): " confirm
            if [[ "$confirm" != "YES" ]]; then
                warn "Operation cancelled."
                return 1
            fi
            log "Formatting $target as ext4 (journaled, 0% root reserve, label 'data') ..."
            mkfs.ext4 -j -m 0 -L data "$target"
        fi
    else
        # No FS: format now
        log "Formatting $target as ext4 (journaled, 0% root reserve, label 'data') ..."
        mkfs.ext4 -j -m 0 -L data "$target"
    fi

    # Mount point
    read -p "Enter mount point (e.g., /mnt/data): " mount_point
    if [[ -z "$mount_point" ]]; then
        error "Mount point cannot be empty."
        return 1
    fi
    if [[ ! -d "$mount_point" ]]; then
        mkdir -p "$mount_point"
        log "Created mount point: $mount_point"
    else
        if [ -n "$(ls -A "$mount_point" 2>/dev/null)" ]; then
            warn "Mount point $mount_point is not empty."
            read -p "Continue and mount over existing contents? (y/N): " cont_nonempty
            if [[ ! "$cont_nonempty" =~ ^[Yy]$ ]]; then
                warn "Operation cancelled."
                return 1
            fi
        fi
    fi

    # Determine FS type (for fstab)
    local fs_type
    fs_type="$(blkid -o value -s TYPE "$target" 2>/dev/null || echo ext4)"

    # Get UUID (prefer filesystem UUID)
    local uuid use_partuuid=false
    uuid="$(blkid -s UUID -o value "$target" 2>/dev/null || true)"
    if [[ -z "$uuid" ]]; then
        warn "Filesystem UUID not found; falling back to PARTUUID."
        uuid="$(blkid -s PARTUUID -o value "$target" 2>/dev/null || true)"
        if [[ -z "$uuid" ]]; then
            error "No UUID/PARTUUID available for $target; refusing to write fstab."
            return 1
        fi
        use_partuuid=true
    fi

    # Mount now
    log "Mounting $target to $mount_point ..."
    if ! mount "$target" "$mount_point"; then
        error "Mount failed."
        return 1
    fi
    log "Mounted $target to $mount_point"

    # Backup fstab
    cp /etc/fstab /etc/fstab.backup.$(date +%s)

    # Add to fstab?
    read -p "Add to /etc/fstab for automatic mounting? (y/n): " add_fstab
    if [[ "$add_fstab" =~ ^[Yy]$ ]]; then
        read -p "Enter mount options [default: defaults]: " mount_opts
        mount_opts=${mount_opts:-defaults}

        if [[ "$use_partuuid" == true ]]; then
            echo "PARTUUID=$uuid $mount_point $fs_type $mount_opts 0 2" >> /etc/fstab
        else
            echo "UUID=$uuid $mount_point $fs_type $mount_opts 0 2" >> /etc/fstab
        fi
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
# SECTION 5: Timezone Configuration
# ============================================
configure_timezone() {
    log "Starting timezone configuration..."

    if ! command -v timedatectl >/dev/null 2>&1; then
        error "timedatectl command not found. This system may not use systemd."
        return 1
    fi

    echo ""
    info "Current time configuration:"
    timedatectl status
    echo ""

    echo "Available U.S. timezones:"
    echo "  1. Pacific Time (America/Los_Angeles)"
    echo "  2. Mountain Time (America/Denver)"
    echo "  3. Central Time (America/Chicago)"
    echo "  4. Eastern Time (America/New_York)"
    echo "  5. Alaska Time (America/Anchorage)"
    echo "  6. Hawaii Time (Pacific/Honolulu)"
    echo "  7. Other (manual entry)"
    echo ""
    read -p "Select timezone [1-7]: " tz_choice

    local tz=""
    case "$tz_choice" in
        1) tz="America/Los_Angeles" ;;
        2) tz="America/Denver" ;;
        3) tz="America/Chicago" ;;
        4) tz="America/New_York" ;;
        5) tz="America/Anchorage" ;;
        6) tz="Pacific/Honolulu" ;;
        7)
            read -p "Enter a valid timezone (e.g., America/New_York): " tz
            ;;
        *)
            warn "Invalid option. No changes made."
            return 1
            ;;
    esac

    # Validate the timezone exists on this system
    if ! timedatectl list-timezones 2>/dev/null | grep -Fxq "$tz"; then
        error "Invalid or unavailable timezone: '$tz'"
        info  "Tip: run 'timedatectl list-timezones | grep -i <city>' to find valid names."
        return 1
    fi

    log "Setting timezone to: $tz"
    if timedatectl set-timezone "$tz"; then
        log "Timezone successfully set to $tz ✓"
    else
        error "Failed to set timezone to $tz"
        return 1
    fi

    echo ""
    info "Updated time configuration:"
    timedatectl status

    # ---- Time sync via htpdate (temporary install) ----
    echo ""
    info "Synchronizing system clock via htpdate (temporary)..."
    local installed_htpdate_temp=false
    export DEBIAN_FRONTEND=noninteractive

    if ! command -v htpdate >/dev/null 2>&1; then
        log "Installing htpdate..."
        # Keep these guarded so set -e doesn't kill the script
        if ! apt-get update -y >/dev/null 2>&1; then
            warn "apt-get update failed; attempting install anyway"
        fi
        if apt-get install -y --no-install-recommends htpdate >/dev/null 2>&1; then
            installed_htpdate_temp=true
            log "htpdate installed ✓"
        else
            error "Failed to install htpdate; cannot perform HTTP time sync"
            return 1
        fi
    fi

    # Try up to 5 times until htpdate says the clock needs no updating
    local attempts=5
    local synced=false
    for ((i=1; i<=attempts; i++)); do
        local out
        out="$(htpdate -s google.com 2>&1 || true)"
        echo "$out"
        if echo "$out" | grep -qiE "No time correction needed"; then
            synced=true
            log "Time is synchronized (attempt $i) ✓"
            break
        fi
        sleep 2
    done

    if [[ "$synced" != true ]]; then
        warn "htpdate did not report 'No time correction needed' after $attempts attempts"
    fi

    # --- Log current time and UTC offset after sync ---
    # Get timezone name (if available), local time with zone, and UTC time
    local tz_name offset now utcnow
    tz_name="$(timedatectl show -p Timezone --value 2>/dev/null || echo "unknown")"
    # Prefer %:z (±HH:MM); fallback to %z (±HHMM) if %:z unsupported
    offset="$(date +%:z 2>/dev/null || date +%z)"
    now="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    utcnow="$(TZ=UTC date '+%Y-%m-%d %H:%M:%S UTC')"

    info "Timezone: $tz_name"
    info "Local time: $now (UTC$offset)"
    info "UTC time:   $utcnow"

    # Capture into report if enabled
    if [[ "${REPORT_MODE:-false}" == "true" ]]; then
        {
            echo ""
            echo "Time after synchronization:"
            echo "  Timezone: $tz_name"
            echo "  Local: $now (UTC$offset)"
            echo "  UTC:   $utcnow"
        } >> "$REPORT_FILE"
    fi

    # Remove htpdate if we installed it
    if [[ "$installed_htpdate_temp" == true ]]; then
        log "Removing temporary htpdate package..."
        if apt-get purge -y htpdate >/dev/null 2>&1; then
            apt-get autoremove -y >/dev/null 2>&1 || true
            log "htpdate removed ✓"
        else
            warn "Failed to purge htpdate (you can remove it later with 'apt purge htpdate')"
        fi
    fi

    return 0
}


# ============================================
# SECTION 7: Report Generation
# ============================================

initialize_report() {
    local hostname timestamp
    hostname="$(hostname)"
    timestamp="$(date +"%Y%m%d_%H%M%S")"

    mkdir -p "$REPORT_DIR"

    REPORT_FILE="$REPORT_DIR/ambient_system-config-report_${hostname}_${timestamp}.txt"
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
            # tolerate missing files
            if compgen -G "/etc/*-release" > /dev/null; then
                cat /etc/*-release 2>&1
            else
                echo "No *-release files found."
            fi

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
            if command -v lspci >/dev/null 2>&1; then
                lspci
            else
                echo "lspci not installed."
            fi

            echo ""
            echo "USB Devices:"
            if command -v lsusb >/dev/null 2>&1; then
                lsusb 2>&1
            else
                echo "lsusb not installed."
            fi

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

    echo ""
    echo "=========================================="
    report_section "BASIC SYSTEM VERIFICATION"
    verify_commands || true

    echo ""
    echo "=========================================="
    run_all_hardware_checks || true

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
        echo "          AmbientOS Appliance         "
        echo "      System Configuration Script     "
        echo "      version 0.13 - 10232025 - jk    "
        echo "======================================"
        echo "System Verification:"
        echo "  1. Pre-Flight: Verify Basic System Requirements"
        echo ""
        echo "Hardware Verification:"
        echo "  2. Check Network Interfaces"
        echo "  3. Check NVIDIA GPU & Drivers"
        echo "  4. Check CPU Info"
        echo "  5. Check Memory Modules"
        echo "  6. Check Power Supplies"
        echo "  7. Check RAID Controller"
        echo "  8. Run ALL Hardware Checks"
        echo ""
        echo "System Configuration:"
        echo "  9.  Configure Netplan"
        echo "  10. Configure Timezone"
        echo "  11. Format and Mount Volume"
        echo ""
        echo "Reporting:"
        echo "  12. Generate Full System Report (Archive)"
        echo "  13. View Recent Reports"
        echo ""
        echo "  14. Run Everything"
        echo "  99. Exit"
        echo ""
        read -p "Select an option: " choice

        case $choice in
            1) verify_commands || true ;;
            2) check_network_interfaces || true ;;
            3) check_nvidia_gpu || true ;;
            4) check_cpu || true ;;
            5) check_memory || true ;;
            6) check_power_supplies || true ;;
            7) check_raid_controller || true ;;
            8) run_all_hardware_checks || true ;;
            9) configure_netplan ;;
            10) configure_timezone ;;
            11) format_and_mount ;;
            12) generate_full_report ;;
            13)
                if [[ -d "$REPORT_DIR" ]]; then
                    log "Recent reports in $REPORT_DIR:"
                    ls -lth "$REPORT_DIR" | head -20
                else
                    warn "No reports found in $REPORT_DIR"
                fi
                ;;
            14)
                read -p "Generate report while running all tasks? (y/n): " gen_report
                if [[ "$gen_report" =~ ^[Yy]$ ]]; then
                    initialize_report
                fi

                # Run verification first, then hardware checks
                verify_commands || true
                echo ""
                run_all_hardware_checks || true
                echo ""
                configure_netplan && format_and_mount

                if [[ "$gen_report" =~ ^[Yy]$ ]]; then
                    finalize_report
                fi
                ;;
            99)
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
