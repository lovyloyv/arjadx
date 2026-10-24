import collections, json, pathlib, re, struct
from lxml import etree as E

P = pathlib.Path(__file__).parent
b = (P / "AndroidManifest.original.axml").read_bytes()
chunks = json.loads((P / "chunks.json").read_text(encoding="utf8"))
nodes = json.loads((P / "nodes.json").read_text(encoding="utf8"))
byoff = {n["offset"]: n for n in nodes}
ANDROID = "http://schemas.android.com/apk/res/android"


def make_xml(compact=False):
    stack = []
    root = None
    removed_permissions = 0
    for c in chunks:
        if c["type"] == "0x102":
            n = byoff[c["offset"]]
            tag = n["name"]
            attrs = []
            replacements = []
            for i, a in enumerate(n["attrs"]):
                if (
                    compact
                    and not a["ns"]
                    and not (
                        tag == "manifest"
                        and a["name"]
                        in (
                            "package",
                            "platformBuildVersionCode",
                            "platformBuildVersionName",
                        )
                    )
                ):
                    continue
                aname = a["name"]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", aname):
                    replacements.append((i, aname))
                    aname = f"obfuscation_attr_{i}"
                if a["ns"]:
                    aname = "{" + a["ns"] + "}" + aname
                attrs.append((aname, a["value"]))
            elem = E.Element(
                tag, dict(attrs), nsmap={"android": ANDROID} if root is None else None
            )
            if root is None:
                root = elem
            elif stack:
                stack[-1].append(elem)
            for i, aname in replacements:
                elem.append(
                    E.Comment(
                        " Original attribute "
                        + str(i)
                        + " name, JSON escaped: "
                        + json.dumps(aname, ensure_ascii=True)
                        + " ; exact record in nodes.json "
                    )
                )
            stack.append(elem)
        elif c["type"] == "0x103":
            elem = stack.pop()
            if compact and elem.tag == "uses-permission":
                name = elem.get("{" + ANDROID + "}name", "")
                if not name.startswith("android.permission.") and not name.endswith(
                    ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
                ):
                    elem.getparent().remove(elem)
                    removed_permissions += 1
    if compact:
        root.insert(
            0,
            E.Comment(
                " Analyst view: omitted "
                + str(removed_permissions)
                + " generated uses-permission entries and all unnamespaced junk attributes. Full forensic content is in recovered.xml and nodes.json. "
            ),
        )
    else:
        root.insert(
            0,
            E.Comment(
                " Analyst XML serialization. Illegal XML attribute names are replaced with obfuscation_attr_N and preserved exactly as JSON in adjacent comments. Original AXML bytes are unchanged in AndroidManifest.original.axml; exact decoded records in nodes.json. "
            ),
        )
    return E.tostring(root, encoding="UTF-8", xml_declaration=True, pretty_print=True)


for name, compact in [("recovered.xml", False), ("manifest.meaningful.xml", True)]:
    data = make_xml(compact)
    E.fromstring(data)
    (P / name).write_bytes(data)

# Strip the two pre-root junk chunks and normalize all attributes to 20-byte records.
# Preserve every genuine node, every string-pool item, and every attribute's 20-byte content.
out = []
changes = []
for c in chunks:
    p = int(c["offset"], 16)
    sz = c["size"]
    typ = int(c["type"], 16)
    if p in (0x8927C, 0x89B10):
        changes.append(
            {
                "offset": hex(p),
                "action": "removed pre-root injected chunk",
                "type": hex(typ),
                "size": sz,
            }
        )
        continue
    chunk = b[p : p + sz]
    if typ == 0x102:
        astart, asz, nattrs = struct.unpack_from("<HHH", b, p + 24)
        aoff = p + c["header_size"] + astart
        attrs = b"".join(b[aoff + i * asz : aoff + i * asz + 20] for i in range(nattrs))
        chunk = bytearray(b[p : p + 36] + attrs)
        struct.pack_into("<I", chunk, 4, len(chunk))
        struct.pack_into("<HH", chunk, 24, 20, 20)
        changes.append(
            {
                "offset": hex(p),
                "action": "normalized attribute layout",
                "oldStart": astart,
                "oldStride": asz,
                "attributeCount": nattrs,
                "oldSize": sz,
                "newSize": len(chunk),
            }
        )
    out.append(chunk)
body = b"".join(out)
(P / "AndroidManifest.normalized.axml").write_bytes(
    struct.pack("<HHI", 3, 8, 8 + len(body)) + body
)
(P / "normalization.json").write_text(json.dumps(changes, indent=2), encoding="utf8")
print(
    "Valid XML views written; normalized AXML",
    len(body) + 8,
    "bytes; original",
    len(b),
    "bytes",
)
