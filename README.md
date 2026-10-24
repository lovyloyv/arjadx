# ARJADX

The paper for this repository is at: [A RAT that breaks JADX.]()

This repository contains scripts and supporting artifacts from the analysis of an Android remote access trojan (RAT) hidden inside a fake Play Store wrapper. The analysis explores how malformed binary XML and unreachable DEX payloads disrupt JADX, how these structures can be normalized for inspection, and how the wrapper conceals an encrypted credit-card phishing RAT.

The scripts are copied as-is from the workspace used during the analysis and may need adjustments before you can use them in your own environment.

## Scripts

- [`scripts/inspect_manifest.py`](scripts/inspect_manifest.py): Inspects the original binary Android manifest and exports its chunks, nodes, strings, and a raw text reconstruction for analysis.
- [`scripts/normalize_manifest.py`](scripts/normalize_manifest.py): Uses the manifest inspection outputs to produce readable XML views and a normalized binary manifest, removing injected pre-root chunks and correcting attribute layouts.
- [`scripts/examine_dex.py`](scripts/examine_dex.py): Extracts `classes.dex` from the original APK and indexes its strings, types, fields, methods, and code offsets for inspection and repair.
- [`scripts/repair_payload_tails.py`](scripts/repair_payload_tails.py): Uses the DEX index to replace malformed trailing array-data payloads with equal-length NOPs, recomputes the DEX checksums, and records the repairs.

## Samples

The ZIP in `sample/` contains the decrypted second-stage APK extracted from the first-stage wrapper. The original first-stage APK is available on [MalwareBazaar](https://bazaar.abuse.ch/sample/0d9e970507baf8216c3a338d09d24e47d78a500b3b20d08836a8dc0e0282aeac/), as linked in the paper.

**Do not run the file in `sample/` or the sample provided on MalwareBazaar that the paper links to. These files contain malware.** The password for the ZIP in `sample/` is `DONOTRUNME`.
