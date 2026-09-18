"""Bounded local verifier transport; no shell, network or unbounded output buffer."""
import os
import selectors
import signal
import subprocess
import time


def run_verifier(command, *, input, timeout=10):
    if (type(input) is not bytes or len(input) > 65536
            or type(timeout) not in (int, float) or isinstance(timeout, bool)
            or not 0 < timeout <= 60):
        raise ValueError('invalid verifier request bounds')
    deadline = time.monotonic() + timeout
    output = bytearray()
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, start_new_session=True) as process:
        completed = False
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdin.fileno(), False)
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                if input:
                    selector.register(process.stdin, selectors.EVENT_WRITE)
                else:
                    process.stdin.close()
                pending = memoryview(input)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in selector.select(remaining):
                        if key.fileobj is process.stdin:
                            try:
                                written = os.write(process.stdin.fileno(), pending[:4096])
                            except BlockingIOError:
                                continue
                            pending = pending[written:]
                            if not pending:
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            try:
                                chunk = os.read(process.stdout.fileno(), 66 - len(output))
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(process.stdout)
                            else:
                                output.extend(chunk)
                                if len(output) > 65:
                                    raise ValueError('excessive verifier output')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                code = process.wait(timeout=remaining)
                completed = True
                return subprocess.CompletedProcess(command, code, bytes(output))
        finally:
            # A verifier may spawn a descendant that inherits stdout. Kill the
            # isolated process group on every incomplete run so that descendant
            # cannot outlive a timeout or keep the bounded pipe open forever.
            if not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
