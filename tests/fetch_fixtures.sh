#!/bin/bash
# Fetch proxy node fixtures from multiple sources for e2e testing.
# Each source gets its own subdirectory under fixtures/.
# Run: bash tests/fetch_fixtures.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/fixtures"
mkdir -p "$DIR"

# Helper: fetch a raw URL file
fetch_raw() {
    local source="$1" protocol="$2" url="$3"
    local out="$DIR/$source/${protocol}.txt"
    mkdir -p "$DIR/$source"
    echo -n "  ${protocol}: "
    curl -sSL --retry 2 --max-time 30 "$url" -o "$out"
    local lines
    lines=$(wc -l < "$out" | tr -d ' ')
    echo "$lines URLs"
}

# Helper: fetch a base64-encoded file and decode it (also handles raw fallback)
fetch_auto() {
    local source="$1" protocol="$2" url="$3"
    local out="$DIR/$source/${protocol}.txt"
    mkdir -p "$DIR/$source"
    echo -n "  ${protocol}: "
    curl -sSL --retry 2 --max-time 30 "$url" | base64 -d 2>/dev/null > "$out"

    local lines
    lines=$(wc -l < "$out" | tr -d ' ')
    if [ "$lines" -gt 0 ]; then
        echo "$lines URLs (base64 decoded)"
        return
    fi

    # base64 decode produced empty output — try raw instead
    curl -sSL --retry 2 --max-time 30 "$url" > "$out"
    lines=$(wc -l < "$out" | tr -d ' ')
    echo "$lines URLs (raw)"
}

# ============================================================
# Source 1: Surfboardv2ray/TGParse (Telegram channel parser)
# ============================================================
echo "=== [1/5] Surfboardv2ray/TGParse ==="
BASE="https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main"
fetch_auto "tgparse" "mixed"   "$BASE/splitted/mixed"
fetch_auto "tgparse" "ss"      "$BASE/splitted/ss"
fetch_auto "tgparse" "vmess"   "$BASE/splitted/vmess"
fetch_auto "tgparse" "vless"   "$BASE/splitted/vless"
fetch_auto "tgparse" "trojan"  "$BASE/splitted/trojan"
fetch_raw  "tgparse" "socks"   "$BASE/python/socks"

# ============================================================
# Source 2: Epodonios/v2ray-configs (every 5 min, highest frequency)
# ============================================================
echo "=== [2/5] Epodonios/v2ray-configs ==="
BASE="https://raw.githubusercontent.com/Epodonios/v2ray-configs/main"
fetch_raw  "epodonios" "all"      "$BASE/All_Configs_Sub.txt"
fetch_raw  "epodonios" "vmess"    "$BASE/Splitted-By-Protocol/vmess.txt"
fetch_auto  "epodonios" "vless"   "$BASE/Splitted-By-Protocol/vless.txt"
fetch_auto  "epodonios" "trojan"  "$BASE/Splitted-By-Protocol/trojan.txt"
fetch_auto  "epodonios" "ss"      "$BASE/Splitted-By-Protocol/ss.txt"

# ============================================================
# Source 3: Danialsamadi/v2go (every 6h, country-split, dedup+port check)
# ============================================================
echo "=== [3/5] Danialsamadi/v2go ==="
BASE="https://raw.githubusercontent.com/Danialsamadi/v2go/main"
fetch_raw  "v2go" "all"      "$BASE/AllConfigsSub.txt"
fetch_raw  "v2go" "vmess"    "$BASE/Splitted-By-Protocol/vmess.txt"
fetch_auto  "v2go" "vless"   "$BASE/Splitted-By-Protocol/vless.txt"
fetch_auto  "v2go" "trojan"  "$BASE/Splitted-By-Protocol/trojan.txt"
fetch_auto  "v2go" "ss"      "$BASE/Splitted-By-Protocol/ss.txt"
fetch_auto  "v2go" "hy2"     "$BASE/Splitted-By-Protocol/hy2.txt"
fetch_auto  "v2go" "tuic"    "$BASE/Splitted-By-Protocol/tuic.txt"

# ============================================================
# Source 4: miladtahanian/Config-Collector (every 30min, Iran-focused)
# ============================================================
echo "=== [4/5] miladtahanian/Config-Collector ==="
BASE="https://raw.githubusercontent.com/miladtahanian/Config-Collector/main"
fetch_raw  "miladtahanian" "mixed"  "$BASE/mixed_iran.txt"
fetch_raw  "miladtahanian" "vless"  "$BASE/vless_iran.txt"
fetch_raw  "miladtahanian" "vmess"  "$BASE/vmess_iran.txt"
fetch_raw  "miladtahanian" "trojan" "$BASE/trojan_iran.txt"
fetch_raw  "miladtahanian" "ss"     "$BASE/ss_iran.txt"

# ============================================================
# Source 5: SoliSpirit/v2ray-configs (every 15min)
# ============================================================
echo "=== [5/5] SoliSpirit/v2ray-configs ==="
BASE="https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main"
fetch_raw  "solispirit" "all"      "$BASE/All_Configs_Sub.txt" 2>/dev/null || echo "  (skipped - may not exist)"

echo ""
echo "Done. Fixtures in $DIR"
echo ""
du -sh "$DIR"/*/
