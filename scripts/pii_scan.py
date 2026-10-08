#!/usr/bin/env python3
"""個人情報スキャナ(ルール検出+任意でaruaru-llmの二次判定)。

使い方: pii_scan.py <bare-or-normal-git-dir> <report.json>
HEADのテキストファイルを走査し、個人情報の疑いを種類・件数・ファイル単位で記録する。
**値そのものはレポートに書かない**(件数と位置のみ)。
終了コード: 0=問題なし(警告のみ含む)、1=公開ミラーを止めるべき検出あり。
"""
import json, os, re, subprocess, sys, urllib.request

MAX_BYTES = 2_000_000
DATA_LIKE = re.compile(r"\.(csv|tsv|jsonl?|ndjson|sql|log|txt|xlsx?|dat)$", re.I)
SKIP_PATH = re.compile(r"(^|/)(testdata|fixtures?|tests?/data|node_modules|vendor|target)/|\.lock$|(^|/)LICENSE", re.I)
SAFE_EMAIL = re.compile(r"(noreply|no-reply|example\.(com|org|net)|localhost|test\.|@.*\.invalid|users\.noreply\.github\.com|anthropic\.com|sentry\.io|@\d+x)", re.I)

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
JP_PHONE = re.compile(r"(?<![\d-])0\d{1,4}-\d{1,4}-\d{3,4}(?![\d-])")
POSTAL_ADDR = re.compile(r"〒\s?\d{3}-?\d{4}\s*[^\n]{0,6}(都|道|府|県)")
MYNUMBER = re.compile(r"(マイナンバー|個人番号)[^\n]{0,20}?(\d{4}[ -]?\d{4}[ -]?\d{4})")
CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])")

def luhn(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9: x -= 9
        s += x
    return s % 10 == 0

def mask_line(line: str) -> str:
    """値を伏せ字にした文脈行(aruaru-llmへ送る用)。"""
    line = EMAIL.sub("<EMAIL>", line)
    line = re.sub(r"\d[\d -]{5,}\d", "<NUM>", line)
    return line.strip()[:200]

def context_lines(text: str, limit: int = 5):
    out = []
    for ln in text.splitlines():
        if EMAIL.search(ln) or JP_PHONE.search(ln) or POSTAL_ADDR.search(ln):
            out.append(mask_line(ln))
            if len(out) >= limit: break
    return out

def git(d, *a, text=True):
    return subprocess.run(["git", "-C", d, *a], capture_output=True, text=text).stdout

def main():
    d, out = sys.argv[1], sys.argv[2]
    files = git(d, "ls-tree", "-r", "--name-only", "HEAD").split("\n")
    findings, block, snippets = [], False, {}
    for path in filter(None, files):
        if SKIP_PATH.search(path): continue
        raw = subprocess.run(["git", "-C", d, "cat-file", "blob", f"HEAD:{path}"], capture_output=True).stdout
        if len(raw) > MAX_BYTES or b"\0" in raw[:4096]: continue
        try: text = raw.decode("utf-8")
        except UnicodeDecodeError: continue
        counts = {}
        emails = [m for m in EMAIL.findall(text) if not SAFE_EMAIL.search(m)]
        if emails: counts["email"] = len(emails)
        n = len(JP_PHONE.findall(text));  counts.update({"jp_phone": n} if n else {})
        n = len(POSTAL_ADDR.findall(text)); counts.update({"jp_address": n} if n else {})
        n = len(MYNUMBER.findall(text)); counts.update({"my_number": n} if n else {})
        n = sum(1 for m in CARD.findall(text) if luhn(m)); counts.update({"card_number": n} if n else {})
        if not counts: continue
        data_like = bool(DATA_LIKE.search(path))
        total = sum(counts.values())
        # 厳格に止める: カード番号・マイナンバー・住所、またはデータ系ファイルに多数、または大量
        strict = any(k in counts for k in ("card_number", "my_number", "jp_address"))
        bulk = (data_like and total >= 5) or total >= 30
        level = "block" if (strict or bulk) else "warn"
        findings.append({"path": path, "types": counts, "level": level})
        snippets[path] = context_lines(text)
        block = block or level == "block"
    # 任意: aruaru-llmで曖昧(warn)を二次判定。設定が無ければ何もしない。
    url, tok = os.environ.get("ARUARU_LLM_URL"), os.environ.get("ARUARU_LLM_TOKEN")
    if url and tok:
        for f in findings:
            if f["level"] != "warn": continue
            try:
                req = urllib.request.Request(url.rstrip("/") + "/v1/classify-pii",
                    data=json.dumps({"snippets": snippets.get(f["path"], [])}, ensure_ascii=False).encode("utf-8"),
                    headers={"x-admin-token": tok, "Content-Type": "application/json"})
                r = json.load(urllib.request.urlopen(req, timeout=20))
                f["llm"] = r.get("verdict")
                if r.get("verdict") == "pii": f["level"] = "block"; block = True
            except Exception as e:
                f["llm"] = f"unavailable: {type(e).__name__}"
    json.dump({"block": block, "findings": findings}, open(out, "w"), ensure_ascii=False, indent=1)
    for f in findings:
        print(f"  PII[{f['level']}] {f['path']} {f['types']}")
    sys.exit(1 if block else 0)

if __name__ == "__main__":
    main()
