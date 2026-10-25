"""Small DNS client for demonstrating the decentralized resolver.

Windows' ``nslookup`` cannot target a non-standard UDP port, so the demo uses
this instead. It speaks the same wire format as any other DNS client; nothing
about the query is special.

    python -m dcdns.dig techfest.cs.test
    python -m dcdns.dig techfest.cs.test --all
    python -m dcdns.dig techfest.cs.test --port 5354
"""

from __future__ import annotations

import argparse

from .experiments import DEFAULT_DNS_NODES, Resolver

RCODE_NAMES = {
    -1: "NO RESPONSE",
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Query a DCDNS DNS endpoint")
    parser.add_argument("name", help="domain name, for example techfest.cs.test")
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument(
        "--port", type=int, default=5353,
        help="UDP port (default: 5353, the quorum resolver)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="query the quorum resolver and every registry node",
    )
    args = parser.parse_args()

    if args.all:
        targets: list[tuple[str, str, int]] = [
            ("quorum", args.server, args.port),
            *[(node_id, host, port) for node_id, (host, port) in DEFAULT_DNS_NODES.items()],
        ]
    else:
        targets = [("dns", args.server, args.port)]

    width = max(len(label) for label, _host, _port in targets)
    for label, host, port in targets:
        rcode, answer = Resolver(host, port).query(args.name)
        rcode_name = RCODE_NAMES.get(rcode, f"RCODE{rcode}")
        endpoint = f"{host}:{port}"
        print(f"{label:<{width}}  {endpoint:<18}  {rcode_name:<11}  {answer or '-'}")


if __name__ == "__main__":
    main()
