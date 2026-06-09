#!/usr/bin/env bash
set -euo pipefail

IPT="${IPT:-iptables}"
PREFIX="${PORTFW_CHAIN_PREFIX:-PFWD_}"
ALLOW_CHAIN="${PORTFW_ALLOW_CHAIN:-PFWD_DOCKER_ALLOW}"

usage() {
  cat <<'EOF'
Usage:
  portfw list
  portfw analyze
  portfw set PUBLIC_IP PUBLIC_PORT TARGET_IP TARGET_PORT
  portfw del PUBLIC_IP PUBLIC_PORT
  portfw del-raw PUBLIC_IP PUBLIC_PORT
  portfw save

Examples:
  sudo portfw list
  sudo portfw analyze
  sudo portfw set <public-ip> 1888 <target-ip> 3000
  sudo portfw del <public-ip> 1888
  sudo portfw del-raw <public-ip> 1888
  sudo portfw save

Notes:
  set      creates or switches a managed TCP DNAT forward.
  list     shows managed forwards and direct DNAT rules.
  analyze  scans every nat chain for DNAT, REDIRECT, and chain jumps.
  del      deletes a managed forward created by this script.
  del-raw  deletes old direct DNAT rules for the public IP and port.
  save     persists current iptables rules when netfilter-persistent is installed.

Environment:
  IPT=iptables-legacy portfw list
  IPT=iptables-nft portfw list
  IPT=iptables-legacy portfw analyze
EOF
}

need_root() {
  if [ "${PORTFW_SKIP_ROOT_CHECK:-0}" = "1" ]; then
    return
  fi

  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "ERROR: run as root, for example: sudo portfw $*" >&2
    exit 1
  fi
}

chain_name() {
  local ip="$1"
  local port="$2"
  local clean_ip
  clean_ip="$(printf '%s' "$ip" | tr '.:-' '___')"
  echo "${PREFIX}${clean_ip}_${port}"
}

comment_text() {
  local ip="$1"
  local port="$2"
  echo "portfw ${ip}:${port}"
}

ensure_chain_jump() {
  local table="$1"
  local parent="$2"
  local public_ip="$3"
  local public_port="$4"
  local child="$5"

  "$IPT" -w -t "$table" -C "$parent" \
    -p tcp -d "$public_ip" --dport "$public_port" \
    -j "$child" 2>/dev/null || \
  "$IPT" -w -t "$table" -I "$parent" 1 \
    -p tcp -d "$public_ip" --dport "$public_port" \
    -j "$child"
}

ensure_allow_chain() {
  "$IPT" -w -N "$ALLOW_CHAIN" 2>/dev/null || true

  if "$IPT" -w -L DOCKER-USER >/dev/null 2>&1; then
    "$IPT" -w -C DOCKER-USER -j "$ALLOW_CHAIN" 2>/dev/null || \
      "$IPT" -w -I DOCKER-USER 1 -j "$ALLOW_CHAIN"
  fi

  "$IPT" -w -C "$ALLOW_CHAIN" -j RETURN 2>/dev/null || \
    "$IPT" -w -A "$ALLOW_CHAIN" -j RETURN
}

delete_rules_by_comment() {
  local table="$1"
  local chain="$2"
  local comment="$3"
  local line

  while true; do
    if [ "$table" = "filter" ]; then
      line="$("$IPT" -L "$chain" --line-numbers -n 2>/dev/null | awk -v c="$comment" 'index($0,c)>0 {print $1; exit}')"
      [ -n "$line" ] || break
      "$IPT" -w -D "$chain" "$line"
    else
      line="$("$IPT" -t "$table" -L "$chain" --line-numbers -n 2>/dev/null | awk -v c="$comment" 'index($0,c)>0 {print $1; exit}')"
      [ -n "$line" ] || break
      "$IPT" -w -t "$table" -D "$chain" "$line"
    fi
  done
}

show_direct_dnat_chain() {
  local chain="$1"

  "$IPT" -t nat -S "$chain" 2>/dev/null | awk -v chain="$chain" '
    / -j DNAT / {
      dst = "-"
      dport = "-"
      target = "-"

      for (i = 1; i <= NF; i++) {
        if ($i == "-d" && (i + 1) <= NF) {
          dst = $(i + 1)
          sub(/\/32$/, "", dst)
        }
        if ($i == "--dport" && (i + 1) <= NF) {
          dport = $(i + 1)
        }
        if ($i == "--to-destination" && (i + 1) <= NF) {
          target = $(i + 1)
        }
      }

      printf "  %-10s %-24s -> %s\n", chain, dst ":" dport, target
      found = 1
    }
    END {
      if (!found) {
        printf "  %-10s none\n", chain
      }
    }
  '
}

cmd_analyze() {
  need_root "$@"

  echo "[iptables]"
  echo "  command: $IPT"
  printf "  version: "
  "$IPT" --version 2>/dev/null || echo "unknown"
  echo

  "$IPT" -t nat -S 2>/dev/null | awk '
    function clean_addr(value) {
      if (value == "" || value == "-") {
        return "*"
      }
      sub(/\/32$/, "", value)
      return value
    }

    function endpoint(dst, dport) {
      dst = clean_addr(dst)
      if (dport == "" || dport == "-") {
        dport = "*"
      }
      return dst ":" dport
    }

    function is_terminal_target(target) {
      return target == "ACCEPT" || target == "DROP" || target == "REJECT" || \
        target == "RETURN" || target == "DNAT" || target == "SNAT" || \
        target == "MASQUERADE" || target == "REDIRECT" || target == "MARK" || \
        target == "CONNMARK" || target == "LOG"
    }

    function parse_rule(line, idx,    n, f, i, neg, c) {
      n = split(line, f, " ")

      chain[idx] = f[2]
      proto[idx] = "all"
      src[idx] = "*"
      dst[idx] = "*"
      inif[idx] = "*"
      outif[idx] = "*"
      sport[idx] = "*"
      dport[idx] = "*"
      action[idx] = "-"
      target[idx] = "-"
      comment[idx] = "-"
      raw[idx] = line

      c = line
      if (c ~ /--comment "/) {
        sub(/^.*--comment "/, "", c)
        sub(/".*$/, "", c)
        comment[idx] = c
      }

      for (i = 3; i <= n; i++) {
        neg = ""
        if (f[i] == "!") {
          neg = "!"
          i++
        }

        if (f[i] == "-p" && (i + 1) <= n) {
          proto[idx] = neg f[++i]
        } else if (f[i] == "-s" && (i + 1) <= n) {
          src[idx] = neg f[++i]
        } else if (f[i] == "-d" && (i + 1) <= n) {
          dst[idx] = neg f[++i]
        } else if (f[i] == "-i" && (i + 1) <= n) {
          inif[idx] = neg f[++i]
        } else if (f[i] == "-o" && (i + 1) <= n) {
          outif[idx] = neg f[++i]
        } else if ((f[i] == "--sport" || f[i] == "--sports") && (i + 1) <= n) {
          sport[idx] = neg f[++i]
        } else if ((f[i] == "--dport" || f[i] == "--dports") && (i + 1) <= n) {
          dport[idx] = neg f[++i]
        } else if (f[i] == "-j" && (i + 1) <= n) {
          action[idx] = f[++i]
        } else if ((f[i] == "--to-destination" || f[i] == "--to" || f[i] == "--to-ports") && (i + 1) <= n) {
          target[idx] = f[++i]
        }
      }
    }

    $1 == "-N" {
      user_chain[$2] = 1
    }

    $1 == "-A" {
      count++
      parse_rule($0, count)
    }

    END {
      for (i = 1; i <= count; i++) {
        if ((action[i] in user_chain) || (action[i] != "-" && !is_terminal_target(action[i]))) {
          ep = endpoint(dst[i], dport[i])
          if (ep != "*:*" && !(action[i] in jump_ep)) {
            jump_ep[action[i]] = ep
            jump_proto[action[i]] = proto[i]
            jump_from[action[i]] = chain[i] " -> " action[i]
          }
        }
      }

      print "[NAT port forwards]"
      printf "  %-34s %-7s %-24s %-9s %-24s %s\n", "CHAIN", "PROTO", "MATCH", "ACTION", "TARGET", "DETAILS"
      print  "  ---------------------------------- ------- ------------------------ --------- ------------------------ ------------------------------"

      found_forward = 0
      for (i = 1; i <= count; i++) {
        if (action[i] == "DNAT" || action[i] == "REDIRECT") {
          ep = endpoint(dst[i], dport[i])
          via = chain[i]
          display_proto = proto[i]

          if (ep == "*:*" && (chain[i] in jump_ep)) {
            ep = jump_ep[chain[i]]
            display_proto = jump_proto[chain[i]]
            via = jump_from[chain[i]]
          }

          details = "src=" clean_addr(src[i]) " in=" inif[i] " out=" outif[i] " sport=" sport[i]
          if (comment[i] != "-") {
            details = details " comment=\"" comment[i] "\""
          }

          printf "  %-34s %-7s %-24s %-9s %-24s %s\n", via, display_proto, ep, action[i], target[i], details
          found_forward = 1
        }
      }

      if (!found_forward) {
        print "  none"
      }

      print ""
      print "[NAT chain jumps]"
      printf "  %-34s %-7s %-24s -> %s\n", "FROM", "PROTO", "MATCH", "TO"
      print  "  ---------------------------------- ------- ------------------------ -- ----------------"

      found_jump = 0
      for (i = 1; i <= count; i++) {
        if ((action[i] in user_chain) || (action[i] != "-" && !is_terminal_target(action[i]))) {
          printf "  %-34s %-7s %-24s -> %s\n", chain[i], proto[i], endpoint(dst[i], dport[i]), action[i]
          found_jump = 1
        }
      }

      if (!found_jump) {
        print "  none"
      }
    }
  '
}

cmd_set() {
  local public_ip="$1"
  local public_port="$2"
  local target_ip="$3"
  local target_port="$4"
  local chain
  local comment

  need_root "$@"

  chain="$(chain_name "$public_ip" "$public_port")"
  comment="$(comment_text "$public_ip" "$public_port")"

  "$IPT" -w -t nat -N "$chain" 2>/dev/null || true

  ensure_chain_jump nat PREROUTING "$public_ip" "$public_port" "$chain"
  ensure_chain_jump nat OUTPUT "$public_ip" "$public_port" "$chain"

  "$IPT" -w -t nat -F "$chain"
  "$IPT" -w -t nat -A "$chain" \
    -m comment --comment "$comment" \
    -j DNAT --to-destination "$target_ip:$target_port"

  ensure_allow_chain
  delete_rules_by_comment filter "$ALLOW_CHAIN" "$comment"

  "$IPT" -w -I "$ALLOW_CHAIN" 1 \
    -p tcp -d "$target_ip" --dport "$target_port" \
    -m comment --comment "$comment" \
    -j ACCEPT

  echo "OK: ${public_ip}:${public_port} -> ${target_ip}:${target_port}"
}

cmd_list() {
  local found=0

  need_root "$@"

  echo "[iptables]"
  echo "  command: $IPT"
  printf "  version: "
  "$IPT" --version 2>/dev/null || echo "unknown"
  echo

  echo "[Managed forwards]"
  while read -r chain; do
    [ -n "$chain" ] || continue
    found=1

    "$IPT" -t nat -S "$chain" 2>/dev/null | awk '
      /--comment "portfw / && /--to-destination/ {
        pub=$0
        sub(/^.*--comment "portfw /, "", pub)
        sub(/".*$/, "", pub)

        dst=$0
        sub(/^.*--to-destination /, "", dst)
        sub(/ .*/, "", dst)

        printf "  %-24s -> %s\n", pub, dst
      }
    '
  done < <("$IPT" -t nat -S 2>/dev/null | awk -v p="$PREFIX" '$1=="-N" && index($2,p)==1 {print $2}')

  [ "$found" = "1" ] || echo "  none"

  echo
  echo "[Direct DNAT forwards]"
  show_direct_dnat_chain PREROUTING
  show_direct_dnat_chain OUTPUT

  echo
  echo "[Docker allow chain]"
  if "$IPT" -L "$ALLOW_CHAIN" -n --line-numbers >/dev/null 2>&1; then
    "$IPT" -L "$ALLOW_CHAIN" -n --line-numbers
  else
    echo "  none"
  fi
}

cmd_del() {
  local public_ip="$1"
  local public_port="$2"
  local chain
  local comment

  need_root "$@"

  chain="$(chain_name "$public_ip" "$public_port")"
  comment="$(comment_text "$public_ip" "$public_port")"

  while "$IPT" -w -t nat -C PREROUTING \
    -p tcp -d "$public_ip" --dport "$public_port" \
    -j "$chain" 2>/dev/null; do
    "$IPT" -w -t nat -D PREROUTING \
      -p tcp -d "$public_ip" --dport "$public_port" \
      -j "$chain"
  done

  while "$IPT" -w -t nat -C OUTPUT \
    -p tcp -d "$public_ip" --dport "$public_port" \
    -j "$chain" 2>/dev/null; do
    "$IPT" -w -t nat -D OUTPUT \
      -p tcp -d "$public_ip" --dport "$public_port" \
      -j "$chain"
  done

  if "$IPT" -w -t nat -L "$chain" >/dev/null 2>&1; then
    "$IPT" -w -t nat -F "$chain"
    "$IPT" -w -t nat -X "$chain"
  fi

  if "$IPT" -w -L "$ALLOW_CHAIN" >/dev/null 2>&1; then
    delete_rules_by_comment filter "$ALLOW_CHAIN" "$comment"
  fi

  echo "OK: deleted managed forward ${public_ip}:${public_port}"
}

cmd_del_raw() {
  local public_ip="$1"
  local public_port="$2"
  local chain
  local line

  need_root "$@"

  for chain in PREROUTING OUTPUT; do
    while true; do
      line="$("$IPT" -t nat -L "$chain" --line-numbers -n | awk -v ip="$public_ip" -v dpt="dpt:$public_port" '
        $2=="DNAT" && index($0,ip)>0 && index($0,dpt)>0 {print $1; exit}
      ')"

      [ -n "$line" ] || break
      "$IPT" -w -t nat -D "$chain" "$line"
    done
  done

  echo "OK: deleted direct DNAT rules for ${public_ip}:${public_port}"
}

cmd_save() {
  need_root "$@"

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
  elif command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
  else
    echo "ERROR: netfilter-persistent or iptables-save is required." >&2
    exit 1
  fi
}

case "${1:-}" in
  list)
    cmd_list
    ;;
  analyze)
    cmd_analyze
    ;;
  set)
    [ "$#" -eq 5 ] || { usage; exit 1; }
    cmd_set "$2" "$3" "$4" "$5"
    ;;
  del)
    [ "$#" -eq 3 ] || { usage; exit 1; }
    cmd_del "$2" "$3"
    ;;
  del-raw)
    [ "$#" -eq 3 ] || { usage; exit 1; }
    cmd_del_raw "$2" "$3"
    ;;
  save)
    cmd_save
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
