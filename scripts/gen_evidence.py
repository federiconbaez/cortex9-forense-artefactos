#!/usr/bin/env python3
"""Genera evidence/full_measure.json + actualiza hashes en FULL_MEASURE.md.

Parser section-aware: las claves de monte_carlo solo se llenan dentro del
bloque `=== measure ... ===` / antes de `=== bfs`; las líneas BFS van a
`bfs_lines` y se cruzan con el dict estructurado `bfs`.
"""
from __future__ import annotations

import hashlib
import json
import re
import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "evidence" / "full_measure.raw.txt"
JSON_OUT = ROOT / "evidence" / "full_measure.json"
MD_OUT = ROOT / "evidence" / "FULL_MEASURE.md"
BIN = ROOT / "target" / "release" / "forense-artefactos"


def art_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=3)
    ).strftime("%Y-%m-%d %H:%M:%S ART")


def sha256_file(p: Path) -> str | None:
    if not p.exists():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def parse_raw(text: str) -> dict:
    section = None  # measure | bfs | mutants | other
    monte_carlo: dict[str, str] = {}
    bfs_lines: dict[str, str] = {}
    mutants: list[str] = []
    elapsed_ms = None
    global_flag = None
    trials = None
    mode = None

    for line in text.splitlines():
        s = line.strip()
        if s.startswith("=== measure mode="):
            section = "measure"
            m = re.search(r"mode=(\w+)\s+trials=(\d+)", s)
            if m:
                mode, trials = m.group(1), int(m.group(2))
            continue
        if s.startswith("=== measure global:"):
            section = "measure"
            m = re.search(r"elapsed_ms=(\d+)", s)
            if m:
                elapsed_ms = int(m.group(1))
            if "CUMPLIDO" in s and "NO CUMPLIDO" not in s:
                global_flag = "CUMPLIDO"
            elif "NO CUMPLIDO" in s:
                global_flag = "NO CUMPLIDO"
            continue
        if s.startswith("=== bfs"):
            section = "bfs"
            continue
        if s.startswith("=== mutants"):
            section = "mutants"
            continue
        if s.startswith("===") or s.startswith("EXIT:"):
            section = "other"
            continue
        if "=>" not in s:
            if section == "mutants" and s:
                mutants.append(s)
            continue
        name = s.split(":", 1)[0].strip()
        if section == "measure":
            # No pisar con BFS: solo measure escribe monte_carlo.
            monte_carlo[name] = s
        elif section == "bfs":
            bfs_lines[name] = s
        elif section == "mutants":
            mutants.append(s)

    bfs_struct = {}
    for name, line in bfs_lines.items():
        st = re.search(r"states=(\d+)", line)
        tr = re.search(r"transitions=(\d+)", line)
        vi = re.search(r"violations=(\d+)", line)
        em = re.search(r"elapsed_ms=(\d+)", line)
        bfs_struct[name] = {
            "states": int(st.group(1)) if st else None,
            "transitions": int(tr.group(1)) if tr else None,
            "violations": int(vi.group(1)) if vi else None,
            "elapsed_ms": int(em.group(1)) if em else None,
            "line": line,
        }

    return {
        "mode": mode,
        "trials": trials,
        "elapsed_ms_measure_global": elapsed_ms,
        "global": global_flag,
        "monte_carlo": monte_carlo,
        "bfs": bfs_struct,
        "mutant_lines": mutants,
    }


def main() -> None:
    raw = RAW.read_text(encoding="utf-8")
    parsed = parse_raw(raw)
    # Validación: MC de pin/rpmb/gk debe hablar de mono=/enroll= etc., no states=
    for k in ("pin_counter", "rpmb", "gatekeeper"):
        line = parsed["monte_carlo"].get(k, "")
        if "states=" in line and "mono=" not in line and "enroll=" not in line:
            raise SystemExit(f"BUG: monte_carlo[{k}] parece BFS: {line!r}")
        if k in parsed["bfs"] and "states=" not in parsed["bfs"][k].get("line", ""):
            raise SystemExit(f"BUG: bfs[{k}] sin states=: {parsed['bfs'][k]}")

    detected = sum(1 for m in parsed["mutant_lines"] if "detected=true" in m)
    total = sum(
        1
        for m in parsed["mutant_lines"]
        if m.startswith("pin_")
        or m.startswith("rpmb_")
        or m.startswith("gk_")
        or m.startswith("pwr_")
    )

    evidence = {
        "schema": "cortex9-forense-artefactos/full_measure/v2.1",
        "measured_at_art": art_now(),
        "mode": parsed["mode"],
        "trials": parsed["trials"],
        "preregistro_commit_hint": "docs/PREREGISTRO.md v2 (commit before measure)",
        "command": "cargo build --release && ./target/release/forense-artefactos all --mode full",
        "binary_sha256": sha256_file(BIN),
        "elapsed_ms_measure_global": parsed["elapsed_ms_measure_global"],
        "label": "por construccion",
        "monte_carlo": parsed["monte_carlo"],
        "bfs": {
            k: {kk: vv for kk, vv in v.items() if kk != "line"}
            for k, v in parsed["bfs"].items()
        },
        "bfs_lines": {k: v["line"] for k, v in parsed["bfs"].items()},
        "mutants_detected": detected,
        "mutants_total": total if total else detected,
        "global": parsed["global"],
        "notes": {
            "powercut": (
                "Invariante = contabilidad exacta (fails == intentos_efectivos). "
                "WBV lo viola por SOBRECONTEO (lado seguro ante power-cut). "
                "VBW lo preserva solo si el resultado de un intento interrumpido "
                "nunca se observa; si pudiera observarse antes del write, VBW "
                "seria el orden vulnerable (ese caso NO esta modelado). "
                "Los 1e7 trials repiten el mismo caso determinista (el RNG solo "
                "avanza un u64 descartado). No es un hallazgo de seguridad "
                "hardware; es un modelo de contabilidad bajo un fallo acotado."
            ),
            "parser": "section-aware v2.1: monte_carlo != bfs (fix auditoria Ben)",
        },
        "raw_transcript": raw.strip(),
    }
    JSON_OUT.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    jh = sha256_file(JSON_OUT)
    rh = sha256_file(RAW)
    bh = evidence["binary_sha256"]

    # Regenerar FULL_MEASURE.md con hashes frescos y framing powercut corregido.
    mc_rows = "\n".join(
        f"| `{k}` | `{v}` |" for k, v in sorted(evidence["monte_carlo"].items())
    )
    bfs = evidence["bfs"]
    md = f"""# Evidencia FULL measure (v2.1)

Medido / regenerado: **{evidence['measured_at_art']}** (America/Buenos_Aires).

## Contrato

- Umbrales/semillas: `docs/PREREGISTRO.md` v2, commit **antes** de la medición.
- Comando exacto:
  ```
  cargo build --release
  ./target/release/forense-artefactos all --mode full
  ```
- Generador de evidencia: `scripts/gen_evidence.py` (parser section-aware:
  `monte_carlo` ≠ `bfs`).
- Trials Monte-Carlo: **10_000_000** por artefacto (≥5 órdenes vs v1=100).
- Etiqueta: **por construcción** (corpus = propio modelo).
- Mutantes: sensibilidad del checker; {evidence['mutants_detected']}/{evidence['mutants_total']} detectados.

## Hashes

| Artefacto | SHA-256 |
|-----------|---------|
| `target/release/forense-artefactos` | `{bh}` |
| `evidence/full_measure.json` | `{jh}` |
| `evidence/full_measure.raw.txt` | `{rh}` |

## Monte-Carlo (campos corregidos; no son líneas BFS)

{mc_rows}

## BFS

| Modelo | states | transitions | violations | elapsed_ms |
|--------|-------:|------------:|-----------:|-----------:|
| pin_counter | {bfs.get('pin_counter',{}).get('states')} | {bfs.get('pin_counter',{}).get('transitions')} | {bfs.get('pin_counter',{}).get('violations')} | {bfs.get('pin_counter',{}).get('elapsed_ms')} |
| rpmb | {bfs.get('rpmb',{}).get('states')} | {bfs.get('rpmb',{}).get('transitions')} | {bfs.get('rpmb',{}).get('violations')} | {bfs.get('rpmb',{}).get('elapsed_ms')} |
| gatekeeper | {bfs.get('gatekeeper',{}).get('states')} | {bfs.get('gatekeeper',{}).get('transitions')} | {bfs.get('gatekeeper',{}).get('violations')} | {bfs.get('gatekeeper',{}).get('elapsed_ms')} |

## Mutantes

**{evidence['mutants_detected']}/{evidence['mutants_total']}** detectados.

## Powercut (framing)

Invariante modelado: **contabilidad exacta** (`fails == intentos_efectivos`).

- **WBV (write-before-verify):** ante power-cut tras el write, el invariante
  falla por **sobreconteo** (el disco avanzó sin intento efectivo). Eso es el
  **lado seguro** respecto de subconteo/elusión del contador: el modelo no
  afirma que WBV sea "inseguro", sino que no preserva contabilidad exacta.
- **VBW (verify-before-write):** preserva el invariante **solo bajo el
  supuesto** de que el resultado de un intento interrumpido **nunca se
  observa**. Si el resultado pudiera observarse antes de la escritura, VBW
  sería el orden vulnerable; **ese caso no está representado** en el modelo.
- Los **1e7 trials** de `powercut` **repiten el mismo caso determinista**
  (el seed solo descarta un `u64`); no exploran diversidad de fallos.

Esto **no** se vende como hallazgo de seguridad sobre hardware real.

Elapsed measure global (transcript): **{evidence['elapsed_ms_measure_global']} ms**.

## Fuzzing (smoke)

Ver `evidence/fuzz_smoke.txt` (corrida previa: 706567 runs / 21 s, 0 crashes).

## Kani

**NO VIABLE** en esta caja (no instalado; declarado explícitamente).

## Transcript

Ver `evidence/full_measure.raw.txt` y el campo `raw_transcript` del JSON.
"""
    MD_OUT.write_text(md, encoding="utf-8")
    print("json", jh)
    print("raw", rh)
    print("bin", bh)
    print("mc_pin", evidence["monte_carlo"].get("pin_counter", "")[:80])
    print("bfs_pin", evidence["bfs"].get("pin_counter"))


if __name__ == "__main__":
    main()
