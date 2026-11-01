import subprocess
import sys
import threading
import time
from ping3 import ping

if len(sys.argv) < 3:
    sys.stderr.write(f"Usage: {sys.argv[0]} <tun_ping> <os>\n")
    sys.exit(1)

binary, target_os = sys.argv[1], sys.argv[2].lower()
tunmap = {
    'android':	'dns0',
    'darwin':	'utun5',
    'freebsd':	'tun0',
    'haiku':	'tun/0',
    'linux':	'dns0',
    'netbsd':	'tun0',
    'openbsd':	'tun0',
    'windows':	'tunnel',
}

if target_os not in tunmap:
    sys.stderr.write(f"Missing tun name for {target_os}\n")
    sys.exit(1)

cmd = [binary, tunmap[target_os]]

print(f"[bench] Launching {' '.join(cmd)}", flush=True)

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

def log_tun_bench(stream):
    for line in iter(stream.readline, ''):
        print(f"[tun] {line}", end="", flush=True)
    stream.close()

try:
    time.sleep(1)
    while True:
        line = process.stdout.readline()
        if not line:
            break
        print(f"[tun] {line.strip()}", flush=True)
        if line.startswith('OPEN'):
            break

    if process.poll() is not None:
        print("[bench] Failed to open")
        sys.exit(1)

    output_thread = threading.Thread(
        target=log_tun_bench,
        args=(process.stdout,),
        daemon=True
    )
    output_thread.start()

    print("[bench] Starting ping", flush=True)
    pong = False
    for p in range(5):
        time.sleep(1)
        delay = ping("172.23.53.1", timeout=2, unit='ms')
        if delay:
            pong = True
            print(f"[bench] reply in {round(delay,1)} ms", flush=True)

    time.sleep(1)
    if not pong:
        print("[bench] Failed")
        sys.exit(1)
except KeyboardInterrupt:
    print("\n[bench] Interrupted.")
finally:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    print("[bench] Exited\n")
