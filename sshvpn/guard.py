"""Очистка одного дочернего процесса при исчезновении супервизора."""

import os
import selectors
import signal
import subprocess
import sys


def main():
    descriptor = int(sys.argv[1])
    stopping = False

    def request_stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    child = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=None, close_fds=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while not stopping and child.poll() is None:
                if selector.select(timeout=0.1) and not os.read(descriptor, 1):
                    stopping = True
        return child.returncode if child.returncode is not None else 0
    finally:
        os.close(descriptor)
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
