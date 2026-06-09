# portfw

`portfw` is a small Bash helper for managing temporary TCP port forwarding with `iptables` on Linux hosts.

It is intended for servers where existing Docker containers are already running and you need to switch a public port to a different container service without restarting containers.

## Features

- Show script-managed forwards.
- Analyze all NAT port forwards from `iptables`.
- Temporarily switch a public TCP port to a target IP and port.
- Remove the temporary override and fall back to existing rules.
- Delete older direct DNAT rules when needed.
- Save current iptables rules when persistence is installed.

## Install

Download the script to `/usr/local/sbin/portfw`:

```bash
curl -fsSL https://raw.githubusercontent.com/KamiPasi/portfw/main/portfw.sh \
  | sudo tee /usr/local/sbin/portfw >/dev/null

sudo chmod +x /usr/local/sbin/portfw
```

Verify:

```bash
sudo portfw help
```

## Commands

```bash
sudo portfw list
sudo portfw analyze
sudo portfw set PUBLIC_IP PUBLIC_PORT TARGET_IP TARGET_PORT
sudo portfw del PUBLIC_IP PUBLIC_PORT
sudo portfw del-raw PUBLIC_IP PUBLIC_PORT
sudo portfw save
```

## View Current Forwarding

Use `analyze` to scan the whole `nat` table:

```bash
sudo portfw analyze
```

This prints:

- `DNAT` forwards
- `REDIRECT` rules
- Docker-published ports in the `DOCKER` chain
- custom NAT chains
- chain jumps such as `PREROUTING -> DOCKER`

If expected rules are missing, your system may be using a different iptables backend:

```bash
sudo env IPT=iptables-legacy portfw analyze
sudo env IPT=iptables-nft portfw analyze
```

## Temporarily Switch a Public Port

To override a public port and send new connections to another container/service:

```bash
sudo portfw set <public-ip> 1888 <target-ip> 3000
```

Example with placeholder addresses:

```bash
sudo portfw set 203.0.113.10 1888 10.0.0.25 3000
```

Run `set` again to switch the same public port to another target:

```bash
sudo portfw set <public-ip> 1888 <new-target-ip> <new-target-port>
```

`portfw set` rewrites the script-managed forwarding chain for the same `PUBLIC_IP:PUBLIC_PORT`, so it does not keep stacking duplicate managed rules.

## Restore Existing Rules

If the public port previously matched an existing rule, such as a custom NAT chain or Docker rule, remove the temporary override:

```bash
sudo portfw del <public-ip> 1888
```

After deletion, new traffic falls back to the original lower-priority iptables rules.

## Delete Old Direct DNAT Rules

For older hand-written rules directly in `PREROUTING` or `OUTPUT`:

```bash
sudo portfw del-raw <public-ip> <public-port>
```

Use this carefully. It only targets direct DNAT rules matching that public IP and port.

## Save Rules

If `iptables-persistent` or `netfilter-persistent` is installed:

```bash
sudo portfw save
```

On Ubuntu, install persistence with:

```bash
sudo apt update
sudo apt install iptables-persistent
```

Then save:

```bash
sudo portfw save
```

## Notes

- Existing TCP connections may continue using their old conntrack mapping. The switch mainly affects new connections.
- Do not flush conntrack on a busy server unless you understand the impact.
- Avoid editing Docker's `DOCKER` chain directly; Docker may recreate those rules.
- Use `portfw del` to remove temporary overrides created by `portfw set`.
