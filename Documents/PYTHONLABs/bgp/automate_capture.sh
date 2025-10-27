#!/usr/bin/env bash
# automate_capture.sh
# Automated Tshark captures inside network namespaces for BGP failover analysis.
# Usage examples shown at bottom of this file / in the README.

set -euo pipefail
IFS=$'\n\t'

### Defaults
OUTDIR="/tmp/bgp_captures"
DURATION=0            # 0 means run until manually stopped
FILTER='tcp port 179 or icmp'   # capture BGP (tcp/179) and ICMP by default
DETECT_ALL=true
VERBOSE=true

### helpers
log() { if [ "$VERBOSE" = true ]; then echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; fi; }
die() { echo "ERROR: $*" >&2; exit 1; }

### Check dependencies
command -v ip >/dev/null 2>&1 || die "ip (iproute2) not found"
command -v tshark >/dev/null 2>&1 || die "tshark not found. Install Wireshark/tshark (sudo apt install tshark)."

### Parse args
NAMESPACES=()
INTERFACES=()
SIMULATE_CUT_NS=""
SIMULATE_CUT_IF=""
SIMULATE_CUT_DOWN_SECS=5

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespaces) shift; IFS=',' read -r -a NAMESPACES <<< "$1"; DETECT_ALL=false; shift ;;
    --interfaces) shift; IFS=',' read -r -a INTERFACES <<< "$1"; DETECT_ALL=false; shift ;;
    --outdir) shift; OUTDIR="$1"; shift ;;
    --duration) shift; DURATION="$1"; shift ;;
    --filter) shift; FILTER="$1"; shift ;;
    --simulate-cut) shift; SIMULATE_CUT_NS="$1"; SIMULATE_CUT_IF="$2"; SIMULATE_CUT_DOWN_SECS="${3:-5}"; shift 3 ;;
    --no-detect) DETECT_ALL=false; shift ;;
    --quiet) VERBOSE=false; shift ;;
    -h|--help) cat <<EOF
Usage: $0 [options]

Options:
  --namespaces ns1,ns2        comma-separated namespace names to capture in
  --interfaces if1,if2        comma-separated interfaces (names) on host to capture
  --outdir /path              directory to store pcaps (default: /tmp/bgp_captures)
  --duration SECONDS          how long to run captures (0 = until stopped)
  --filter "BPF filter"       tshark capture filter (default: 'tcp port 179 or icmp')
  --simulate-cut NS IF [secs] simulate link down in namespace NS on IF for secs (default 5)
  --no-detect                 don't auto-discover namespaces/interfaces
  --quiet                     suppress logs
  -h, --help                  show this help
EOF
exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

mkdir -p "$OUTDIR"

### Auto-detect namespaces and veth interfaces if requested
if [ "$DETECT_ALL" = true ]; then
  log "Auto-detecting network namespaces and veth interfaces..."
  # list netns
  mapfile -t NAMESPACES < <(ip netns list --no-header | awk '{print $1}' || true)
  # find veth interfaces inside each ns
  INTERFACES=()
  for ns in "${NAMESPACES[@]}"; do
    mapfile -t ifs < <(ip netns exec "$ns" ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^veth|^eth|^ens|^enp' || true)
    for ifn in "${ifs[@]}"; do
      INTERFACES+=("${ns}:${ifn}")
    done
  done
fi

if [ ${#INTERFACES[@]} -eq 0 ]; then
  die "No interfaces found to capture. Provide --interfaces or ensure namespaces exist."
fi

log "Will capture on the following interfaces (format namespace:interface):"
for i in "${INTERFACES[@]}"; do
  log "  $i"
done

### Start captures
PIDS=()
PCAPS=()
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

start_capture() {
  ns="$1"
  ifname="$2"
  safe_ifname="${ifname//\//_}"
  out="$OUTDIR/${ns}_${safe_ifname}_${TIMESTAMP}.pcap"
  log "Starting capture in namespace '$ns' on interface '$ifname' -> $out"
  # run tshark inside namespace; use -i <if> and -f <filter>
  sudo ip netns exec "$ns" tshark -i "$ifname" -f "$FILTER" -w "$out" >/dev/null 2>&1 &
  pid=$!
  PIDS+=("$pid")
  PCAPS+=("$out")
  # small sleep to avoid races
  sleep 0.2
}

# Launch captures for each INTERFACES item
for item in "${INTERFACES[@]}"; do
  if [[ "$item" == *:* ]]; then
    ns="${item%%:*}"
    ifn="${item#*:}"
    start_capture "$ns" "$ifn"
  else
    # assume interface name on host (no namespace); use host capture
    out="$OUTDIR/host_${item}_${TIMESTAMP}.pcap"
    log "Starting host capture on interface '$item' -> $out"
    sudo tshark -i "$item" -f "$FILTER" -w "$out" >/dev/null 2>&1 &
    pid=$!
    PIDS+=("$pid")
    PCAPS+=("$out")
    sleep 0.2
  fi
done

log "Started ${#PIDS[@]} tshark process(es). PIDs: ${PIDS[*]}"

### Trap to stop captures cleanly
cleanup() {
  log "Stopping captures..."
  for p in "${PIDS[@]}"; do
    if kill -0 "$p" >/dev/null 2>&1; then
      sudo kill "$p" || true
      # allow tshark to flush and exit
      sleep 0.2
      sudo wait "$p" 2>/dev/null || true
    fi
  done
  log "Captures saved to:"
  for f in "${PCAPS[@]}"; do
    echo "  $f"
  done
}
trap cleanup EXIT INT TERM

### Optionally simulate cable cut
if [ -n "$SIMULATE_CUT_NS" ] && [ -n "$SIMULATE_CUT_IF" ]; then
  log "Simulating link down in ns=$SIMULATE_CUT_NS interface=$SIMULATE_CUT_IF for ${SIMULATE_CUT_DOWN_SECS}s"
  sudo ip netns exec "$SIMULATE_CUT_NS" ip link set "$SIMULATE_CUT_IF" down || log "Failed to set link down (maybe interface name wrong)"
  if [ "$SIMULATE_CUT_DOWN_SECS" -gt 0 ]; then
    sleep "$SIMULATE_CUT_DOWN_SECS"
    sudo ip netns exec "$SIMULATE_CUT_NS" ip link set "$SIMULATE_CUT_IF" up || log "Failed to set link up"
    log "Link restored"
  fi
fi

### If duration provided, sleep then exit (EXIT trap will fire)
if [ "$DURATION" -gt 0 ]; then
  log "Running captures for $DURATION seconds..."
  sleep "$DURATION"
  log "Duration complete, exiting..."
  exit 0
else
  log "Captures running. Press Ctrl-C to stop and save pcaps (or kill this script)."
  # wait indefinitely until signal triggers trap
  while true; do sleep 3600; done
fi
