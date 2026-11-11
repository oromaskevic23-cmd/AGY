"""Disposable cooperative worker for offline AGY stop tests only.

This is deliberately fixed test code, not a general-purpose agent sandbox.
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("cooperative", "ignore-stop", "ignore-term"),
                        default="cooperative")
    args = parser.parse_args()
    if args.mode == "ignore-term" and hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    done = threading.Event()

    def activity():
        while not done.wait(0.02):
            # Simulate an active job without any external effects.
            time.monotonic()

    thread = threading.Thread(target=activity, daemon=True)
    thread.start()
    try:
        while True:
            command = sys.stdin.readline()
            if not command:
                time.sleep(0.05)
                continue
            if command == "STOP\n" and args.mode == "cooperative":
                sys.stdout.write("AGY_STOP_ACK\n")
                sys.stdout.flush()
                return 0
            # An unresponsive test worker intentionally ignores the control command.
    finally:
        done.set()


if __name__ == "__main__":
    sys.exit(main())
