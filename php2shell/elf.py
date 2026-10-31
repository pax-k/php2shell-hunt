"""Minimal, dependency-free ELF64 reader for build-to-build diffing.

Only what `php2shell/build_diff.py` needs: sections, symbols, GNU build-id and
a content hash. Parsing happens on the host, so it works on stock images that
ship no binutils (the official `php:*-apache` images do not).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

SHT_SYMTAB, SHT_STRTAB, SHT_NOTE, SHT_DYNSYM = 2, 3, 7, 11
STT_OBJECT, STT_FUNC, STT_GNU_IFUNC = 1, 2, 10
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
SHN_UNDEF, SHN_XINDEX = 0, 0xFFFF

_SYM = struct.Struct("<IBBHQQ")  # name, info, other, shndx, value, size


class ElfError(ValueError):
    pass


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int
    data: bytes = b""


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    type: int
    bind: int
    shndx: int
    section: str = ""
    table: str = ""

    @property
    def is_func(self) -> bool:
        return self.type in (STT_FUNC, STT_GNU_IFUNC) and self.shndx != SHN_UNDEF


@dataclass
class Elf:
    path: str = ""
    sha256: str = ""
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    build_id: str = ""

    def section(self, name: str) -> Section | None:
        return next((s for s in self.sections if s.name == name), None)

    def named(self, name: str) -> list[Symbol]:
        return [s for s in self.symbols if s.name == name]

    def symbol(self, name: str) -> Symbol | None:
        """Prefer a defined global function, then any defined symbol."""
        hits = [s for s in self.named(name) if s.shndx != SHN_UNDEF]
        if not hits:
            return None
        hits.sort(key=lambda s: (s.bind != STB_GLOBAL, not s.is_func, -s.size))
        return hits[0]

    def functions(self) -> dict[str, Symbol]:
        """One entry per name: prefer global, then the largest definition."""
        best: dict[str, Symbol] = {}
        for sym in self.symbols:
            if not sym.is_func:
                continue
            cur = best.get(sym.name)
            if cur is None or (cur.bind != STB_GLOBAL, -cur.size) > (
                sym.bind != STB_GLOBAL,
                -sym.size,
            ):
                best[sym.name] = sym
        return best


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def _cstr(blob: bytes, off: int) -> str:
    if off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    return blob[off:end if end >= 0 else len(blob)].decode("utf-8", "replace")


def load(path: str) -> Elf:
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] != b"\x7fELF":
        raise ElfError(f"{path}: not an ELF file")
    if blob[4] != 2:
        raise ElfError(f"{path}: only ELF64 is supported")
    if blob[5] != 1:
        raise ElfError(f"{path}: only little-endian ELF is supported")

    shoff = _u64(blob, 40)
    shentsize, shnum, shstrndx = _u16(blob, 58), _u16(blob, 60), _u16(blob, 62)
    if not shoff or not shnum:
        raise ElfError(f"{path}: no section headers")
    if shentsize < 64:
        raise ElfError(f"{path}: unsupported section header size {shentsize}")

    raw = []
    for i in range(shnum):
        o = shoff + i * shentsize
        raw.append(
            (
                _u32(blob, o),
                _u32(blob, o + 4),
                _u64(blob, o + 8),
                _u64(blob, o + 16),
                _u64(blob, o + 24),
                _u64(blob, o + 32),
                _u32(blob, o + 40),
                _u64(blob, o + 56),
            )
        )
    if shstrndx == SHN_XINDEX:
        shstrndx = raw[0][6]  # sh_link of section 0
    strtab = blob[raw[shstrndx][4]: raw[shstrndx][4] + raw[shstrndx][5]]

    sections = []
    for name_off, typ, flags, addr, off, size, link, entsize in raw:
        sections.append(
            Section(
                name=_cstr(strtab, name_off),
                type=typ,
                flags=flags,
                addr=addr,
                offset=off,
                size=size,
                link=link,
                entsize=entsize,
                data=blob[off: off + size],
            )
        )

    symbols: list[Symbol] = []
    seen: set[tuple[str, int, int, int]] = set()
    for sec in sections:
        if sec.type not in (SHT_SYMTAB, SHT_DYNSYM) or not sec.entsize:
            continue
        strings = sections[sec.link].data if sec.link < len(sections) else b""
        for o in range(0, len(sec.data) - _SYM.size + 1, sec.entsize):
            name_off, info, _other, shndx, value, size = _SYM.unpack_from(
                sec.data, o
            )
            name = _cstr(strings, name_off)
            if not name:
                continue
            key = (name, value, shndx, info)
            if key in seen:
                continue
            seen.add(key)
            symbols.append(
                Symbol(
                    name=name,
                    value=value,
                    size=size,
                    type=info & 0xF,
                    bind=info >> 4,
                    shndx=shndx,
                    section=(
                        sections[shndx].name
                        if 0 < shndx < len(sections)
                        else ""
                    ),
                    table=sec.name,
                )
            )

    build_id = ""
    note = next((s for s in sections if s.name == ".note.gnu.build-id"), None)
    if note:
        o = 0
        while o + 12 <= len(note.data):
            namesz, descsz, ntype = (
                _u32(note.data, o),
                _u32(note.data, o + 4),
                _u32(note.data, o + 8),
            )
            o += 12
            name = note.data[o: o + namesz].rstrip(b"\x00")
            o += (namesz + 3) & ~3
            desc = note.data[o: o + descsz]
            o += (descsz + 3) & ~3
            if name == b"GNU" and ntype == 3:
                build_id = desc.hex()
                break

    return Elf(
        path=path,
        sha256=hashlib.sha256(blob).hexdigest(),
        sections=sections,
        symbols=symbols,
        build_id=build_id,
    )


# --------------------------------------------------------------------------
# Offline check
# --------------------------------------------------------------------------
def self_test() -> bool:
    """Round-trip a synthetic ELF64 with one .symtab and one FUNC symbol."""
    body = bytearray(64 + 64 * 4)
    body[0:4] = b"\x7fELF"
    body[4], body[5] = 2, 1
    struct.pack_into("<Q", body, 40, 64)          # e_shoff
    struct.pack_into("<HHH", body, 58, 64, 4, 3)  # shentsize, shnum, shstrndx
    names = b"\x00.shstrtab\x00.symtab\x00.strtab\x00.sym\x00"
    sym = _SYM.pack(1, (STB_GLOBAL << 4) | STT_FUNC, 0, 1, 0x1000, 16)
    strtab = b"\x00sym\x00"
    blob = bytearray(bytes(body) + names + sym + strtab)
    shstr_off = len(body)
    symtab_off = shstr_off + len(names)
    strtab_off = symtab_off + len(sym)
    # section 0 is the null section; shstrndx=3 points at .shstrtab
    for i, (name_off, typ, off, size, link, entsize) in enumerate(
        [
            (0, 0, 0, 0, 0, 0),
            (11, SHT_SYMTAB, symtab_off, len(sym), 2, _SYM.size),
            (19, SHT_STRTAB, strtab_off, len(strtab), 0, 0),
            (1, SHT_STRTAB, shstr_off, len(names), 0, 0),
        ]
    ):
        o = 64 + i * 64
        struct.pack_into("<IIQQQQIIQQ", blob, o, name_off, typ, 0, 0, off,
                         size, link, 0, 0, entsize)
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".so") as fh:
        fh.write(blob)
        fh.flush()
        elf = load(fh.name)
    syms = elf.functions()
    assert "sym" in syms and syms["sym"].value == 0x1000, syms
    assert elf.section(".symtab") is not None
    return True
