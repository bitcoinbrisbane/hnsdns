# hnsdns

A small local DNS server that lets any browser or app reach
[Handshake](https://handshake.org) names without giving up a fast, normal
resolver for everything else.

- **ICANN names** (`.com`, `.au`, `.arpa`, …) go to Cloudflare over
  DNS-over-HTTPS (or any upstream you choose).
- **Everything else** is treated as a Handshake name and resolved iteratively,
  starting at [hnsd](https://github.com/handshake-org/hnsd)'s root server,
  which answers from proofs it verifies against the Handshake chain.

One static Go binary with no cgo, plus hnsd for the chain data.

```
            stub query (browser, OS)
                     │
             hnsdns :53  ── cache (positive + negative, TTL-aware)
                     │
        ┌────────────┴─────────────┐
   TLD in IANA list?          otherwise
        │                          │
 DoH → 1.1.1.1 / 1.0.0.1    hnsd root :5369  (SPV-verified HNS data)
                                   │  referral
                            HNS nameservers → answer
                     (NS hosts & CNAME targets go back through the router,
                      so welcome.nb → ns1.example.com uses the ICANN path)
```

## Quick start (Docker)

```sh
git clone https://github.com/bitcoinbrisbane/hnsdns && cd hnsdns
docker compose up -d
dig @127.0.0.1 welcome.nb       # Handshake
dig @127.0.0.1 example.com      # ICANN, via Cloudflare DoH
```

hnsd needs a minute or two to sync headers on first start; Handshake lookups
return SERVFAIL until it has.

Then point your machine at it:

| OS | How |
|---|---|
| macOS | `sudo networksetup -setdnsservers Wi-Fi 127.0.0.1` (undo: `… Wi-Fi empty`) |
| Linux (systemd-resolved) | in `/etc/systemd/resolved.conf`: `DNS=127.0.0.1` and `Domains=~.`, then `sudo systemctl restart systemd-resolved` |
| Windows | Adapter → IPv4 → Preferred DNS `127.0.0.1` |
| Whole network | run it on a NAS/server, publish `53:53` in compose, and hand that IP out via your router/FortiGate DHCP or DNS forwarder |

### Browsing Handshake sites

- **Turn off the browser's own secure DNS.** Chrome: Settings → Privacy →
  *Use secure DNS* off. Firefox: Settings → Privacy → *DNS over HTTPS* off.
  Otherwise the browser skips system DNS and never sees your resolver.
- Type `http://welcome.nb/` — with the scheme and trailing slash — or the
  address bar treats a bare name as a search.
- Sites with ordinary CA certificates and plain-HTTP sites work. Sites that
  rely only on **DANE** (TLSA records instead of a CA) will still show a
  certificate warning; browsers don't do DANE. See the roadmap.

## Running natively

```sh
make build
# hnsd with its root server on the default 127.0.0.1:5369:
hnsd -n 127.0.0.1:5369 -r 127.0.0.1:5370 &
sudo ./bin/hnsdns -v
```

Using hsd instead of hnsd? Its root server is on `127.0.0.1:5349`:
`-hns-root=127.0.0.1:5349`.

### Flags

| Flag | Default | |
|---|---|---|
| `-listen` | `127.0.0.1:53` | UDP and TCP |
| `-upstream` | `https://1.1.1.1/dns-query,https://1.0.0.1/dns-query` | DoH URLs, or plain `ip:port` servers (not mixed). Keep IP literals if this is the machine's only resolver. |
| `-hns-root` | `127.0.0.1:5369` | Handshake root server(s) |
| `-zone` | | `suffix=ip:port`, repeatable — e.g. `-zone lan=192.168.1.1:53` for local names |
| `-tld-cache` | user cache dir | IANA list is cached so restarts work offline |
| `-tld-refresh` | `24h` | |
| `-cache-size` | `10000` | answers |
| `-ipv6` | `false` | also try IPv6 addresses for HNS nameservers |
| `-v` | | log every query with which path handled it |

`localhost` is answered locally; `.local`, `.onion` and `.invalid` get
NXDOMAIN and never leave the machine.

## How names are split

The router checks the rightmost label against IANA's
[root-zone TLD list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt),
fetched through the ICANN upstream itself so there's no bootstrap loop. Names
under an ICANN TLD can't be Handshake names (Handshake reserves them), so the
split is safe. If the list can't be loaded at all, everything goes through
the hnsd root, which carries its own copy of the ICANN root — slower, but it
still works.

## Security notes

- hnsd verifies Handshake data with Merkle proofs against chain headers, and
  it's on localhost, so the root step is trustless.
- Below the root, answers come from ordinary nameservers over UDP. hnsdns
  rejects out-of-bailiwick glue and randomises query IDs, but **does not yet
  validate DNSSEC** on the Handshake path.
- The ICANN path inherits Cloudflare's DNSSEC validation; Cloudflare sees
  those queries, not your Handshake ones.

## Development

```sh
make test   # go test -race ./...
make vet
make cross  # binaries for macOS, Linux, Windows into dist/
```

Tests run fake root, TLD and upstream servers on `127.0.0.x` loopback
addresses (Linux binds the whole `127/8` by default; on macOS add aliases with
`sudo ifconfig lo0 alias 127.0.0.2` and `.3`, or let those tests skip).

## Roadmap

1. DNSSEC validation on the Handshake path (hnsd's root signs with a known key).
2. **Native Go SPV client** — header sync, Urkel proof verification, HNS
   resource decoding — so hnsd is no longer needed and the whole thing is one
   binary.
3. A local DoH listener, so browsers can keep "secure DNS" on and point it here.
4. A small DANE-checking HTTPS proxy for DANE-only sites.

## License

MIT — see [LICENSE](LICENSE).
