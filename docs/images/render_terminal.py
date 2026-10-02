"""Render a real SkillGuard scan (ANSI output) to a terminal-style PNG.

Usage: python3 render_terminal.py <ansi_file> <out_png>
Keeps the banner + summary + CRITICAL block + risk score, collapses the rest.
"""
import html
import re
import sys

from playwright.sync_api import sync_playwright

FG = {30: "#4b5563", 31: "#ff5f6d", 32: "#3ddc97", 33: "#ffc857", 34: "#5b9dff",
      35: "#c792ea", 36: "#38d6e8", 37: "#e6edf3", 90: "#6b7280", 91: "#ff7b85",
      92: "#5ff0b0", 93: "#ffd97a", 94: "#82b4ff", 95: "#d7a6f5", 96: "#6ee7f5", 97: "#ffffff"}
BG = {40: "#111", 41: "#e5484d", 42: "#2f9e6e", 43: "#d4a017", 44: "#3b6fd8",
      45: "#9b59b6", 46: "#1aa3b5", 47: "#e6edf3", 100: "#374151", 101: "#ff5f6d"}
SGR = re.compile(r"\x1b\[([0-9;]*)m")
OTHER = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def to_html(line: str) -> str:
    out, st = [], {"fg": None, "bg": None, "b": False, "d": False}
    pos = 0

    def span(text):
        if not text:
            return
        css = []
        if st["fg"]:
            css.append(f"color:{st['fg']}")
        if st["bg"]:
            css.append(f"background:{st['bg']};display:inline-block;height:1.42em;vertical-align:top")
        if st["b"]:
            css.append("font-weight:700")
        if st["d"]:
            css.append("opacity:.55")
        t = html.escape(text)
        out.append(f'<span style="{";".join(css)}">{t}</span>' if css else t)

    for m in SGR.finditer(line):
        span(line[pos:m.start()])
        pos = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c] or [0]
        for c in codes:
            if c == 0:
                st = {"fg": None, "bg": None, "b": False, "d": False}
            elif c == 1:
                st["b"] = True
            elif c == 2:
                st["d"] = True
            elif c == 22:
                st["b"] = st["d"] = False
            elif c == 39:
                st["fg"] = None
            elif c == 49:
                st["bg"] = None
            elif c in FG:
                st["fg"] = FG[c]
            elif c in BG:
                st["bg"] = BG[c]
    span(line[pos:])
    return "".join(out)


def plain(s: str) -> str:
    return SGR.sub("", s)


def main(src: str, dst: str) -> None:
    raw = open(src, encoding="utf-8").read()
    raw = OTHER.sub(lambda m: m.group(0) if m.group(0).endswith("m") else "", raw)
    lines = raw.replace("\r", "").split("\n")
    # drop spinner line, keep "Scan complete"
    lines = [l for l in lines if not plain(l).lstrip().startswith("- Scanning")]
    P = [plain(l) for l in lines]
    hi = next(i for i, l in enumerate(P) if l.strip().startswith("HIGH"))
    score = next(i for i, l in enumerate(P) if "╭" in l and i > hi)
    rec_end = len(P)
    while rec_end > 0 and not P[rec_end - 1].strip():
        rec_end -= 1
    hidden = sum(1 for l in P[hi:score] if l.strip().startswith("►"))
    keep = lines[:hi] + [
        f'\x1b[2m    ··· {hidden} more findings (HIGH, MEDIUM, LOW) ···\x1b[22m', ""
    ] + lines[score:rec_end]
    body = "\n".join(to_html(l) for l in keep)
    page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
    html,body{{margin:0;background:transparent}}
    .win{{display:inline-block;margin:24px;border-radius:12px;overflow:hidden;
      background:#0d1117;box-shadow:0 20px 50px rgba(0,0,0,.45),0 0 0 1px #30363d}}
    .bar{{height:38px;background:#161b22;display:flex;align-items:center;gap:8px;padding:0 14px;
      border-bottom:1px solid #30363d;font:13px -apple-system,Segoe UI,sans-serif;color:#8b949e}}
    .dot{{width:12px;height:12px;border-radius:50%}}
    .t{{flex:1;text-align:center;margin-right:52px}}
    pre{{margin:0;padding:18px 26px 22px;color:#e6edf3;
      font:13.5px/1.42 'JetBrains Mono',Menlo,monospace;white-space:pre;
      font-variant-ligatures:none;font-feature-settings:"liga" 0,"calt" 0}}
    .cmd{{color:#3ddc97}}
    </style></head><body><div class="win" id="w">
    <div class="bar"><span class="dot" style="background:#ff5f57"></span>
    <span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>
    <span class="t">skillguard scan ./malicious-skill</span></div>
    <pre><span class="cmd">$</span> skillguard scan ./malicious-skill
{body}</pre></div></body></html>"""
    with sync_playwright() as p:
        b = p.chromium.launch(
            executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            headless=True,
        )
        pg = b.new_page(device_scale_factor=2, viewport={"width": 1000, "height": 800})
        pg.set_content(page)
        pg.wait_for_timeout(300)
        pg.locator("#w").screenshot(path=dst, omit_background=True)
        b.close()
    print("wrote", dst, "hidden", hidden)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
