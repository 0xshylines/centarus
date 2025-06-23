#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
centarus.py
─────────────────────
.NET DLL / EXE dosyalarından (decompiler KULLANMADAN) gömülü hassas
bilgileri tespit eder, sonuçları terminalde renkli gösterir ve CSV / JSON
dosyalarına kaydeder.

Kullanım örnekleri
──────────────────
  # Basit tarama (tek dosya)
  python centarus.py C:\app\my.dll

  # Birden fazla dosya + klasör, recursive, özel pattern dosyası
  python centarus.py C:\bin  C:\tools\a.dll  ^
      --recursive ^
      --patterns custom_patterns.txt ^
      --output findings.csv

  # JSON çıktısı
  python centarus.py C:\bin --output findings.json
"""
import argparse, os, re, json, csv, sys, pathlib, base64, textwrap
from typing import List, Dict, Any
from collections import defaultdict

class C:
    RED   = "\033[91m"
    YEL   = "\033[93m"
    GRN   = "\033[92m"
    CYN   = "\033[96m"
    MAG   = "\033[95m"
    RST   = "\033[0m"
    BOLD  = "\033[1m"

def color(text, clr): return f"{clr}{text}{C.RST}"

def load_patterns(path: str = None) -> Dict[str, List[str]]:
    """patterns.txt =>  kategori|regex  veya  regex  formatı"""
    default_patterns = {
        "password": [
            r'password\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'pwd\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'Password\s*=\s*([^;,"\s]{4,})'
        ],
        "api_key": [
            r'api[_-]?key\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'\b[A-Za-z0-9]{32}\b'
        ],
        "token": [
            r'(?:bearer\s+)?[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{5,}'  # JWT
        ],
        "connection": [
            r'Server=[^;]+;Database=[^;]+;User\s*Id=[^;]+;Password=[^;]+"?'
        ],
        "secret": [
            r'secret\s*[:=]\s*["\']([^"\']{5,})["\']'
        ],
        "base64": [
            r'\b(?:[A-Za-z0-9+/]{40,}={0,2})\b'
        ]
    }

    if not path:
        return default_patterns

    patt: Dict[str, List[str]] = defaultdict(list)
    try:
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                if "|" in ln:
                    cat, rex = ln.split("|", 1)
                    patt[cat.strip()].append(rex.strip())
                else:
                    patt["custom"].append(ln)
        return patt or default_patterns
    except Exception as e:
        print(color(f"[!] Pattern dosyası okunamadı ({e}) – varsayılanlar kullanılıyor", C.YEL))
        return default_patterns

def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    ascii_re   = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
    unicode_re = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len)

    strings = [m.group().decode("ascii",  errors="ignore")     for m in ascii_re.finditer(data)]
    strings += [m.group().decode("utf-16le", errors="ignore") for m in unicode_re.finditer(data)]
    return list(set(s for s in strings if len(s.strip()) >= min_len))

def analyze_strings(strings: List[str], patterns: Dict[str, List[str]],
                    file_name: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for s_idx, s in enumerate(strings):
        for category, regex_list in patterns.items():
            for rex in regex_list:
                for m in re.finditer(rex, s, flags=re.IGNORECASE):
                    val = m.group()
                    if is_false_positive(val):
                        continue
                    findings.append({
                        "file": file_name,
                        "category": category,
                        "match": val,
                        "context": shorten(s),
                        "string_index": s_idx
                    })
    return findings

def is_false_positive(value: str) -> bool:
    placeholders = {"null", "none", "empty", "string", "password", "secret", "key"}
    v = value.strip(' "\'').lower()
    return (len(v) < 3) or (v in placeholders)

def shorten(txt: str, length: int = 120) -> str:
    return (txt[:length] + "...") if len(txt) > length else txt

def write_report(findings: List[Dict[str, Any]], out_path: str):
    if not out_path:
        return
    ext = pathlib.Path(out_path).suffix.lower()
    try:
        if ext == ".json":
            with open(out_path, "w", encoding="utf-8") as jf:
                json.dump(findings, jf, indent=2, ensure_ascii=False)
        else:  # .csv
            keys = ["file", "category", "match", "context"]
            with open(out_path, "w", newline="", encoding="utf-8") as cf:
                w = csv.DictWriter(cf, fieldnames=keys)
                w.writeheader()
                for row in findings:
                    w.writerow({k: row.get(k, "") for k in keys})
        print(color(f"[+] Rapor kaydedildi → {out_path}", C.GRN))
    except Exception as e:
        print(color(f"[!] Rapor yazılamadı: {e}", C.RED))

def walk_targets(targets: List[str], recursive: bool) -> List[str]:
    found: List[str] = []
    for t in targets:
        p = pathlib.Path(t)
        if not p.exists():
            print(color(f"[!] Yol bulunamadı: {t}", C.RED))
            continue
        if p.is_file() and p.suffix.lower() in {".dll", ".exe"}:
            found.append(str(p))
        elif p.is_dir():
            if recursive:
                for f in p.rglob("*"):
                    if f.suffix.lower() in {".dll", ".exe"}:
                        found.append(str(f))
            else:
                for f in p.glob("*.dll"):
                    found.append(str(f))
                for f in p.glob("*.exe"):
                    found.append(str(f))
    return found

def scan_file(path: str, patterns: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    try:
        data = pathlib.Path(path).read_bytes()
    except Exception as e:
        print(color(f"[!] {path} okunamadı: {e}", C.RED))
        return []
    strings = extract_strings(data)
    return analyze_strings(strings, patterns, os.path.basename(path))

def banner():
    print("\n" + color("═" * 70, C.CYN))
    print(color("   DLL / EXE Secret Scanner  –  CENTARUS   ", C.BOLD + C.MAG))
    print(color("    Created by Shylines   ", C.CYN))
    print(color("═" * 70, C.CYN))

def main():
    banner()
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent("""\
            .NET derlemelerindeki (DLL/EXE) gömülü gizli anahtar, şifre,
            connection string vb. bilgileri decompiler kullanmadan bulur.
            """)
    )
    ap.add_argument("targets", nargs="+",
                    help="Taranacak dosya veya klasörler")
    ap.add_argument("--patterns", "-p",
                    help="Özel pattern dosyası (varsayılan regex seti yerine)")
    ap.add_argument("--output", "-o",
                    help="findings.csv veya findings.json olarak rapor dosyası")
    ap.add_argument("--recursive", "-r", action="store_true",
                    help="Klasörleri alt dizinleriyle birlikte tara")
    args = ap.parse_args()

    patterns = load_patterns(args.patterns)
    all_targets = walk_targets(args.targets, args.recursive)

    if not all_targets:
        print(color("[!] Taranacak dosya bulunamadı", C.RED))
        sys.exit(1)

    total_findings: List[Dict[str, Any]] = []
    for f in all_targets:
        print(color(f"\n[•] {f}", C.BOLD))
        f_findings = scan_file(f, patterns)
        if f_findings:
            print(color(f"    ↳ {len(f_findings)} bulgu", C.YEL))
        else:
            print(color("    ↳ Temiz", C.GRN))
        total_findings.extend(f_findings)

    print(color("\n" + "═" * 70, C.CYN))
    print(color(f"Toplam taranan dosya  : {len(all_targets)}", C.BOLD))
    print(color(f"Toplam bulgu          : {len(total_findings)}", C.BOLD))
    cat_counts = defaultdict(int)
    for fx in total_findings:
        cat_counts[fx['category']] += 1
    for cat, cnt in cat_counts.items():
        print(f"  {cat:<15} : {cnt}")

    if args.output:
        write_report(total_findings, args.output)

    if total_findings:
        print(color("\nÖrnek bulgular:", C.CYN))
        for i, f in enumerate(total_findings[:10], 1):
            print(f"{i:2d}. {color(f['category'].upper(), C.MAG)}  {shorten(f['match'], 60)}")
            print(f"    → {shorten(f['context'])}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[CTRL-C] İptal edildi")