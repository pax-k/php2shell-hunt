#!/usr/bin/env python3
"""Corpus generator/mutator for the disclosure fuzzing campaign.

  python3 fuzz/gen.py --mode unserialize --n 20000 --out corpus.b64
  python3 fuzz/gen.py --mode multipart   --n 20000 --out corpus.b64
  python3 fuzz/gen.py --mode string      --n 20000 --out corpus.b64
  python3 fuzz/gen.py --mode xml         --n 20000 --out corpus.b64

Emits base64 lines consumable by fuzz/asan_run.php. Deterministic per --seed.
Extend SEEDS per mode for a track; the mutator is generic.
"""
import argparse
import base64
import random

SEEDS = {
    "unserialize": [
        b'a:1:{i:0;s:1:"x";}',
        b'a:2:{i:0;O:8:"stdClass":0:{}i:0;i:1;}',
        b's:4:"abcd";', b'S:4:"\\61\\62\\63\\64";',
        b'a:3:{i:0;R:1;i:1;r:2;i:2;d:1.5;}',
        b'O:8:"stdClass":2:{s:1:"a";i:1;s:2:"bb";s:2:"cc";}',
        b'a:1018:{' + b'i:0;N;' * 1016 + b'i:9;O:8:"stdClass":0:{}i:9;i:1;}',
        b'"' + b'A' * 64, b's:999:"x";', b'i:1;' + b'junk',
        b'a:1:{i:0;C:11:"ArrayObject":0:{}}',
    ],
    "session": [
        b'a|i:1;', b'a|s:4:"abcd";', b'a|O:8:"stdClass":0:{}',
        b'a|' + b'a:1018:{' + b'i:0;N;' * 1016 + b'i:9;O:8:"stdClass":0:{}i:9;i:1;}',
        b'k|R:1;', b'k|r:1;', b'k|S:4:"\\61\\62\\63\\64";',
    ],
    "multipart": [
        b'name="a"\r\n\r\nx',
        b'name="a[]"\r\n\r\nx',
        b'name="a' + b'\x81' + b'"\r\n\r\nx',
        b'name="a"; filename="b"\r\n\r\nx',
        b'name="a"; filename="' + b'A' * 300 + b'"',
        b'name="' + b'A' * 9000 + b'"',
    ],
    "string": [
        b'%s%s%s%s', b'%1$s%2$s', b'%999999999s', b'%.*s',
        b'\x81\x82\x83', b'\xff\xfe\xfd', b'\x00' * 32,
    ],
    "xml": [
        b'<r/>', b'<r a="1"/>', b'<r xmlns:x="u"><x:a/></r>',
        b'<!DOCTYPE r [<!ENTITY e "v">]><r>&e;</r>',
        b'<r>' + b'<a>' * 200 + b'</a>' * 200 + b'</r>',
    ],
}
UNSOLICITED = bytes(range(256))


def mutate(rng, b):
    b = bytearray(b)
    for _ in range(rng.randint(1, 4)):
        op = rng.random()
        if op < 0.35 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op < 0.6 and b:
            del b[rng.randrange(len(b)):][:rng.randint(1, 8)]
        elif op < 0.8:
            i = rng.randrange(len(b) + 1)
            b[i:i] = bytes(rng.choice(UNSOLICITED) for _ in range(rng.randint(1, 8)))
        else:
            # length-token mutation (s:N: / a:N:{)
            b = bytearray(bytes(b).replace(b'1018', str(rng.choice([0, 1, 1017, 1019, 65535])).encode(), 1)
                          if b'1018' in bytes(b) else bytes(b))
            if b:
                i = rng.randrange(len(b))
                b[i] = rng.randrange(32, 127)
    return bytes(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=sorted(SEEDS))
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    seeds = SEEDS[args.mode]
    with open(args.out, "w") as fh:
        for i in range(args.n):
            base = seeds[i % len(seeds)] if i < len(seeds) * 2 else rng.choice(seeds)
            fh.write(base64.b64encode(mutate(rng, base)).decode() + "\n")
    print(f"wrote {args.n} inputs to {args.out}")


if __name__ == "__main__":
    main()
