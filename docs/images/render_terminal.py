"""Render a real skillguard scan (ANSI output) to a terminal-style PNG.

Regenerate (needs playwright and Chrome):

    skillguard scan examples/malicious-skill > /tmp/scan.ansi
    python3 docs/images/render_terminal.py /tmp/scan.ansi docs/images/scan-demo.png

Usage: python3 render_terminal.py <ansi_file> <out_png>

Layout: a wide terminal window with TWO panes side by side, splash on the left
and the verdict + findings on the right. One tall column photographed badly at
README width (it ran past the fold and the text shrank to ~7px); two panes make
the image landscape, so it fits on screen at close to full text size.

Long Code: lines are truncated to the pane width: a 215-character snippet is
unreadable in a screenshot anyway, and it is what made the old image wrap.
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

# Pane budget. 62 characters at 12px JetBrains Mono keeps two panes inside a
# 1000px viewport, which is what lets the PNG display near 1:1 in a README.
COLS = 62
FONT_PX = 12
LINE_H = 1.42


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
            css.append(f"background:{st['bg']};display:inline-block;height:{LINE_H}em;vertical-align:top")
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


def is_art(line: str) -> bool:
    """Box drawing, ASCII banner and block bars must not be truncated."""
    return bool(re.search(r"[╔╗╚╝║╭╮╰╯│─█▄▀]", line))


def fit(html_line: str, text: str) -> str:
    if len(text) <= COLS or is_art(text):
        return html_line
    # Truncate the plain text, then re-escape: colour resets are re-emitted so a
    # cut line cannot leak one colour into the next.
    return html.escape(text[: COLS - 1].rstrip()) + "…"


def index_of(plain_lines, pred, start=0):
    for i in range(start, len(plain_lines)):
        if pred(plain_lines[i]):
            return i
    return None


def main(src: str, dst: str) -> None:
    raw = open(src, encoding="utf-8").read()
    raw = OTHER.sub(lambda m: m.group(0) if m.group(0).endswith("m") else "", raw)
    lines = [l for l in raw.replace("\r", "").split("\n")
             if not plain(l).lstrip().startswith("- Scanning")]
    P = [plain(l) for l in lines]

    def find(pred, start=0):
        i = index_of(P, pred, start)
        if i is None:
            raise SystemExit(f"render_terminal: could not find expected block ({pred})")
        return i

    # Blocks are located by content, so a rule change that adds findings does
    # not silently shift the crop.
    scan_i = find(lambda l: "✔ Scan complete" in l)
    box_top = max(i for i in range(scan_i) if "╔" in P[i])        # version box
    box_bottom = find(lambda l: "╚" in l, box_top)
    banner_top = find(lambda l: "█" in l)
    verdict_top = find(lambda l: "╔" in l, scan_i)
    verdict_bottom = find(lambda l: "╚" in l, verdict_top)
    summary_i = find(lambda l: "SCAN SUMMARY" in l, verdict_bottom)
    findings_i = find(lambda l: "CODE ANALYSIS FINDINGS" in l, summary_i)
    crit_i = find(lambda l: l.strip().startswith("CRITICAL  ("), findings_i)
    high_i = find(lambda l: l.strip().startswith("HIGH"), crit_i)
    score_top = find(lambda l: "ASSESSMENT" in l, high_i)
    score_bottom = find(lambda l: "╰" in l, score_top)
    high_count = re.search(r"\((\d+)", plain(P[high_i])).group(1)

    def block(a, b, drop_blank=True):
        rows = []
        for i in range(a, b + 1):
            if drop_blank and not plain(lines[i]).strip():
                continue
            rows.append(fit(to_html(lines[i]), plain(lines[i])))
        return rows

    # Left pane: what ran and what it counted. Right pane: the verdict and the
    # reasons. Splitting this way also balances the panes, so the divider runs
    # the full height instead of ending at the shorter one.
    left = (
        block(banner_top, box_bottom) + [""] + block(scan_i, scan_i)
        + [""] + block(summary_i, findings_i - 1)
    )
    right = (
        block(verdict_top, verdict_bottom) + [""] + block(findings_i, crit_i)
        + block(crit_i + 1, high_i - 1)
        + [f'<span style="opacity:.55">    ··· {high_count} more findings (HIGH, MEDIUM, LOW) ···</span>']
        + [""] + block(score_top, score_bottom)
    )

    def pane(rows, title="", first=""):
        head = f'<span class="cmd">{title}</span>\n' if title else ""
        return f"<pre>{head}" + "\n".join(rows) + "</pre>"

    page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
    html,body{{margin:0;background:transparent}}
    .win{{display:inline-block;margin:20px;border-radius:12px;overflow:hidden;
      background:#0d1117;box-shadow:0 20px 50px rgba(0,0,0,.45),0 0 0 1px #30363d}}
    .bar{{height:34px;background:#161b22;display:flex;align-items:center;gap:8px;padding:0 14px;
      border-bottom:1px solid #30363d;font:12px -apple-system,Segoe UI,sans-serif;color:#8b949e}}
    .dot{{width:11px;height:11px;border-radius:50%}}
    .t{{flex:1;text-align:center;margin-right:48px}}
    .panes{{display:flex;align-items:flex-start}}
    .panes pre{{margin:0;padding:10px 22px 16px;color:#e6edf3;
      font:{FONT_PX}px/{LINE_H} 'JetBrains Mono',Menlo,monospace;white-space:pre;
      font-variant-ligatures:none;font-feature-settings:"liga" 0,"calt" 0}}
    .split{{width:1px;align-self:stretch;background:#30363d;margin:0}}
    .cmd{{color:#3ddc97}}
    </style></head><body><div class="win" id="w">
    <div class="bar"><span class="dot" style="background:#ff5f57"></span>
    <span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>
    <span class="t">skillguard scan ./malicious-skill</span></div>
    <div class="panes">{pane([f'<span class="cmd">$</span> skillguard scan ./malicious-skill'] + left)}
    <div class="split"></div>
    {pane(right)}</div></div></body></html>"""

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
    print("wrote", dst)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
