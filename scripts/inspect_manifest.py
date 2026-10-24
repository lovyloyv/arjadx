import json, pathlib, struct, collections, html, sys

sys.stdout.reconfigure(encoding="utf-8")

P = pathlib.Path(__file__).parent
b = (P / "AndroidManifest.original.axml").read_bytes()
u16 = lambda p: struct.unpack_from("<H", b, p)[0]
u32 = lambda p: struct.unpack_from("<I", b, p)[0]
strings = []


def readlen16(p):
    n = u16(p)
    p += 2
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | u16(p)
        p += 2
    return n, p


def readlen8(p):
    n = b[p]
    p += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | b[p]
        p += 1
    return n, p


def s(i):
    return strings[i] if i < len(strings) else ("" if i == 0xFFFFFFFF else f"INDEX_{i}")


chunks = []
nodes = []
p = 8
depth = 0
xml = []
while p + 8 <= len(b):
    typ, hs, sz = struct.unpack_from("<HHI", b, p)
    if sz < 8 or p + sz > len(b):
        print("BAD", hex(p), hex(typ), hs, sz)
        break
    c = {"offset": hex(p), "type": hex(typ), "header_size": hs, "size": sz}
    chunks.append(c)
    if typ == 1:
        count, styles, flags, start, style = struct.unpack_from("<IIIII", b, p + 8)
        c.update(count=count, styles=styles, flags=hex(flags), string_start=hex(start))
        for i in range(count):
            off = p + start + u32(p + hs + i * 4)
            if flags & 0x100:
                chars, off = readlen8(off)
                length, off = readlen8(off)
                text = b[off : off + length].decode("utf8", "replace")
            else:
                length, off = readlen16(off)
                text = b[off : off + length * 2].decode("utf-16le", "replace")
            strings.append(text)
    elif typ in (0x100, 0x101):
        c["prefix"] = s(u32(p + hs))
        c["namespace"] = s(u32(p + hs + 4))
    elif typ == 0x102:
        ns, name = struct.unpack_from("<II", b, p + 16)
        astart, asz, nattrs, idx, cls, sty = struct.unpack_from("<HHHHHH", b, p + 24)
        c.update(
            name=s(name),
            ns=s(ns),
            attribute_start=astart,
            attribute_size=asz,
            attribute_count=nattrs,
        )
        attrs = []
        for i in range(nattrs):
            off = p + 16 + astart + i * asz
            ans, aname, raw, size, res0, dtype, data = struct.unpack_from(
                "<IIIHBBI", b, off
            )
            value = (
                s(raw)
                if raw != 0xFFFFFFFF
                else (
                    s(data)
                    if dtype == 3
                    else ("true" if data else "false")
                    if dtype == 18
                    else str(data)
                    if dtype == 16
                    else f"@0x{data:08x}"
                    if dtype == 1
                    else f"0x{data:x}"
                )
            )
            attrs.append(
                {
                    "ns": s(ans),
                    "name": s(aname),
                    "value": value,
                    "raw": raw,
                    "type": dtype,
                    "data": data,
                    "offset": hex(off),
                }
            )
        node = {"offset": hex(p), "depth": depth, "name": s(name), "attrs": attrs}
        nodes.append(node)
        xml.append(
            "  " * depth
            + "<"
            + s(name)
            + "".join(
                " "
                + ("android:" if a["ns"] else "")
                + a["name"]
                + "="
                + json.dumps(a["value"], ensure_ascii=False)
                for a in attrs
            )
            + ">"
        )
        depth += 1
    elif typ == 0x103:
        depth -= 1
        name = s(u32(p + 20))
        c["name"] = name
        xml.append("  " * max(0, depth) + "</" + name + ">")
    p += sz
(P / "chunks.json").write_text(
    json.dumps(chunks, indent=2, ensure_ascii=False), encoding="utf8"
)
(P / "nodes.json").write_text(
    json.dumps(nodes, indent=2, ensure_ascii=False), encoding="utf8"
)
(P / "strings.json").write_text(
    json.dumps(strings, indent=2, ensure_ascii=False), encoding="utf8"
)
(P / "recovered.raw.txt").write_text("\n".join(xml), encoding="utf8")
print(
    "chunks",
    len(chunks),
    "nodes",
    len(nodes),
    "strings",
    len(strings),
    "end",
    hex(p),
    "file",
    hex(len(b)),
)
print("types", collections.Counter(c["type"] for c in chunks))
print("first chunks", chunks[:10])
print("last chunks", chunks[-3:])
for n in nodes:
    if n["name"] in (
        "manifest",
        "application",
        "activity",
        "service",
        "receiver",
        "provider",
    ):
        print(n["offset"], n["name"], [(a["name"], a["value"]) for a in n["attrs"]])
