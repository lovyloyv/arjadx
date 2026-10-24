import json, struct, zipfile, pathlib

B = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).resolve().parent
z = zipfile.ZipFile(next(B.glob("*.apk")))
d = z.read("classes.dex")
OUT.joinpath("classes.dex").write_bytes(d)
u16 = lambda p: struct.unpack_from("<H", d, p)[0]
u32 = lambda p: struct.unpack_from("<I", d, p)[0]


def uleb(p):
    v = 0
    s = 0
    while True:
        b = d[p]
        p += 1
        v |= (b & 127) << s
        s += 7
        if b < 128:
            return v, p


def string(p):
    n, p = uleb(p)
    e = d.index(0, p)
    return d[p:e].decode("utf8", "replace")


strings = [string(u32(u32(60) + 4 * i)) for i in range(u32(56))]
types = [strings[u32(u32(68) + 4 * i)] for i in range(u32(64))]


def proto(i):
    p = u32(76) + i * 12
    r = types[u32(p + 4)]
    ps = u32(p + 8)
    return (
        "("
        + ("".join(types[u16(ps + 4 + 2 * j)] for j in range(u32(ps))) if ps else "")
        + ")"
        + r
    )


methods = []
for i in range(u32(88)):
    p = u32(92) + i * 8
    c, pr, n = struct.unpack_from("<HHI", d, p)
    methods.append(types[c] + "->" + strings[n] + proto(pr))
fields = []

for i in range(u32(80)):
    p = u32(84) + i * 8
    c, t, n = struct.unpack_from("<HHI", d, p)
    fields.append(types[c] + "->" + strings[n] + ":" + types[t])

codes = []
for i in range(u32(96)):
    p = u32(100) + i * 32
    cl, access, sup, interfaces, src, ann, cd, sd = struct.unpack_from("<8I", d, p)
    if not cd:
        continue
    counts = []
    p = cd
    for j in range(4):
        v, p = uleb(p)
        counts.append(v)
    for count in counts[:2]:
        idx = 0
        for j in range(count):
            v, p = uleb(p)
            idx += v
            flags, p = uleb(p)
    for count in counts[2:]:
        idx = 0
        for j in range(count):
            v, p = uleb(p)
            idx += v
            flags, p = uleb(p)
            co, p = uleb(p)
            if co:
                reg, ins, outs, tries, debug, sz = struct.unpack_from("<HHHHII", d, co)
                codes.append(
                    dict(
                        index=idx,
                        name=methods[idx],
                        flags=flags,
                        code_off=co,
                        insn_off=co + 16,
                        registers=reg,
                        ins=ins,
                        outs=outs,
                        tries=tries,
                        debug_off=debug,
                        size=sz,
                    )
                )

OUT.joinpath("dex_index.json").write_text(
    json.dumps(
        dict(methods=methods, fields=fields, types=types, strings=strings, codes=codes),
        indent=2,
    ),
    encoding="utf8",
)
for c in codes:
    if "OIAqRhwucWJTZIByYJmWqWWPOHeKzpF;" in c["name"]:
        print(json.dumps(c))
        b = d[c["insn_off"] : c["insn_off"] + c["size"] * 2]
        for x in range(0, len(b), 16):
            print(f'{x//2:04x} {c["insn_off"]+x:08x}: ' + b[x : x + 16].hex(" "))
