import json, struct, pathlib, hashlib, zlib

O = pathlib.Path(__file__).resolve().parent
d = bytearray(O.joinpath("classes.dex").read_bytes())

idx = json.loads(O.joinpath("dex_index.json").read_text())
tail = []
suspicious = []

for c in idx["codes"]:
    off = c["insn_off"]
    size = c["size"]
    for pc in range(size - 4):
        p = off + pc * 2
        if d[p : p + 2] != b"\0\3":
            continue
        w, n = struct.unpack_from("<HI", d, p + 2)
        units = 4 + (w * n + 1) // 2
        if pc + units == size:
            rec = {
                **c,
                "payload_pc": pc,
                "payload_off": p,
                "width": w,
                "count": n,
                "units": units,
                "preceding_unit": d[p - 2 : p].hex(),
            }
            tail.append(rec)
            if w not in (1, 2, 4, 8):
                suspicious.append(rec)
                d[p : off + size * 2] = b"\0" * (units * 2)
                break

d[12:32] = hashlib.sha1(d[32:]).digest()
struct.pack_into("<I", d, 8, zlib.adler32(d[12:]) & 0xFFFFFFFF)

O.joinpath("classes.analysis.dex").write_bytes(d)
O.joinpath("invalid_tail_payloads.json").write_text(
    json.dumps(suspicious, indent=2), encoding="utf8"
)

print(
    json.dumps(
        {
            "methods_with_code": len(idx["codes"]),
            "trailing_payloads": len(tail),
            "invalid_trailing_payloads": len(suspicious),
            "widths": {
                str(w): sum(c["width"] == w for c in suspicious)
                for w in sorted({c["width"] for c in suspicious})
            },
            "preceding_unit": {
                h: sum(c["preceding_unit"] == h for c in suspicious)
                for h in sorted({c["preceding_unit"] for c in suspicious})
            },
        },
        indent=2,
    )
)
