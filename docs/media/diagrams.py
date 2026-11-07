"""Draw the PosturaNet workflow diagrams (README and docs) as static SVGs.

Colors are the design-system tokens (docs/04_DESIGN_SYSTEM.md section 10.2), light by default
and dark under `prefers-color-scheme: dark`. Re-run after a pipeline or wording change:

    python docs/media/diagrams.py

Writes `docs/media/diagram-*.svg`. No network, nothing outside `docs/media/`.
"""

# ruff: noqa: E501  (SVG template lines)
from __future__ import annotations

import html
from collections.abc import Callable
from pathlib import Path

OUT = Path(__file__).resolve().parent

SANS = "Inter,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "'JetBrains Mono','Cascadia Mono',Consolas,monospace"

# token: (light, dark)
TOKENS = {
    "bg": ("#FFFFFF", "#0B0E0F"),
    "surf": ("#F5F7F8", "#1A1F1D"),
    "bd": ("#D9DEE2", "#2A302E"),
    "bds": ("#B8C0C6", "#3A423F"),
    "tx": ("#14202E", "#E8E6E1"),
    "mu": ("#5A6878", "#919693"),
    "acc": ("#3B5BDB", "#4C6EF5"),
    "ok": ("#1A7F37", "#2FBF71"),
    "warn": ("#B35900", "#EAB308"),
    "crit": ("#C62828", "#E5484D"),
}
ARROW_TONES = ("mu", "acc", "ok", "warn", "crit")


def _css() -> str:
    def rules(i: int) -> str:
        out = []
        for name, pair in TOKENS.items():
            c = pair[i]
            out.append(f".f-{name}{{fill:{c}}}.s-{name}{{stroke:{c}}}")
        return "".join(out)

    return (
        f"{rules(0)}"
        f"@media (prefers-color-scheme: dark){{{rules(1)}}}"
        f".sans{{font-family:{SANS}}}.mono{{font-family:{MONO}}}"
    )


# A line of text inside a box: (text, color token, size, bold, mono)
Line = tuple[str, str, float, bool, bool]


def ln(
    text: str, tone: str = "mu", size: float = 12, bold: bool = False, mono: bool = False
) -> Line:
    return (text, tone, size, bold, mono)


class Diagram:
    def __init__(self, width: int, height: int, title: str) -> None:
        self.w, self.h, self.title = width, height, title
        self.parts: list[str] = []

    def text(
        self,
        x: float,
        y: float,
        text: str,
        tone: str = "mu",
        size: float = 12,
        bold: bool = False,
        mono: bool = False,
        anchor: str = "middle",
    ) -> None:
        weight = ' font-weight="700"' if bold else ""
        self.parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" class="f-{tone} {"mono" if mono else "sans"}" '
            f'font-size="{size}" text-anchor="{anchor}"{weight}>{html.escape(text)}</text>'
        )

    def box(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        lines: list[Line],
        edge: str = "bd",
        fill: str = "surf",
        dash: bool = False,
        width: float = 1.25,
    ) -> None:
        d = ' stroke-dasharray="6 5"' if dash else ""
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
            f'class="f-{fill} s-{edge}" stroke-width="{width}"{d}/>'
        )
        heights = [size * 1.45 for _, _, size, _, _ in lines]
        top = y + (h - sum(heights)) / 2
        for (text, tone, size, bold, mono), lh in zip(lines, heights, strict=True):
            self.text(x + w / 2, top + lh * 0.74, text, tone, size, bold, mono)
            top += lh

    def arrow(
        self,
        points: list[tuple[float, float]],
        tone: str = "mu",
        dash: bool = False,
        head: bool = True,
    ) -> None:
        d = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(points))
        dashed = ' stroke-dasharray="5 4"' if dash else ""
        marker = f' marker-end="url(#a-{tone})"' if head else ""
        self.parts.append(
            f'<path d="{d}" fill="none" class="s-{tone}" stroke-width="1.5" '
            f'stroke-linejoin="round"{dashed}{marker}/>'
        )

    def render(self) -> str:
        markers = "".join(
            f'<marker id="a-{t}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="f-{t}"/></marker>'
            for t in ARROW_TONES
        )
        body = "\n".join(self.parts)
        return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" role="img" aria-label="{html.escape(self.title)}">
<title>{html.escape(self.title)}</title>
<style>{_css()}</style>
<defs>{markers}</defs>
<rect width="{self.w}" height="{self.h}" rx="12" class="f-bg"/>
{body}
</svg>
"""


# --- diagrams


def pipeline() -> Diagram:
    """The fix pipeline: nine stages, each able to stop with a reason and no PR."""
    d = Diagram(1060, 400, "How PosturaNet turns a finding into a pull request")
    bw, bh, gap, pad = 188, 96, 18, 24
    xs = [pad + i * (bw + gap) for i in range(5)]
    y_in, y1 = 24, 92
    y2 = y1 + bh + 48

    inputs = [
        ("Security Hub finding", "acc"),
        ("your Terraform repo", "acc"),
        ("logs, read-only role", "acc"),
    ]
    for i, (label, tone) in enumerate(inputs):
        d.box(xs[i] + 14, y_in, bw - 28, 32, [ln(label, tone, 12, True)], edge="bds", fill="bg")
        d.arrow([(xs[i] + bw / 2, y_in + 32), (xs[i] + bw / 2, y1 - 2)], "acc")

    row1 = [
        ("ingest", "the finding, parsed", ln("stops: unsupported control", "crit", 11.5)),
        ("locate", "Terraform block + owner", ln("stops: no clear match", "crit", 11.5)),
        ("evidence", "who really connects", ln("no logs: report only", "crit", 11.5)),
        ("contract", "what must keep working", ln("stops: rare source unreviewed", "crit", 11.5)),
        ("synthesize", "smallest fix (Z3)", ln("stops: nothing fits", "crit", 11.5)),
    ]
    # Row 2 runs right to left, under row 1.
    row2 = [
        ("validate", "plan scope + checks", ln("stops: any check fails", "crit", 11.5)),
        ("deliver", "GitHub pull request", ln("stops: duplicate or freeze", "crit", 11.5)),
        ("you merge", "a person reviews it", ln("PosturaNet never merges", "acc", 11.5)),
        ("verify", "re-check after apply", ln("regressed: revert PR", "warn", 11.5)),
        ("record", "run record in the repo", ln("signed evidence (Pro)", "mu", 11.5)),
    ]
    for i, (name, what, last) in enumerate(row1):
        d.box(xs[i], y1, bw, bh, [ln(name, "tx", 15, True, True), ln(what, "mu", 12), last])
        if i < 4:
            d.arrow([(xs[i] + bw, y1 + bh / 2), (xs[i + 1] - 2, y1 + bh / 2)])
    for j, (name, what, last) in enumerate(row2):
        i = 4 - j
        merge = name == "you merge"
        d.box(
            xs[i],
            y2,
            bw,
            bh,
            [ln(name, "acc" if merge else "tx", 15, True, not merge), ln(what, "mu", 12), last],
            edge="acc" if merge else "bd",
            fill="bg" if merge else "surf",
            dash=merge,
        )
        if j < 4:
            d.arrow([(xs[i], y2 + bh / 2), (xs[i - 1] + bw + 2, y2 + bh / 2)])
    d.arrow([(xs[4] + bw / 2, y1 + bh), (xs[4] + bw / 2, y2 - 2)])

    y_note = y2 + bh + 36
    d.parts.append(
        f'<rect x="{pad}" y="{y_note - 10}" width="10" height="10" rx="2" class="f-crit"/>'
    )
    d.text(
        pad + 18,
        y_note,
        "Every stop prints the reason and the next step, opens no PR and exits 3. When in doubt, PosturaNet stops.",
        "mu",
        12.5,
        anchor="start",
    )
    return d


def change_gate() -> Diagram:
    """Every change to a security group, S3 or IAM policy is checked against its contract."""
    d = Diagram(1060, 392, "How PosturaNet checks a change made by a person or an AI agent")
    mid = 172
    ys = [mid - 108, mid, mid + 108]
    bh = 64

    ax, aw = 24, 200
    d.box(
        ax,
        mid - 66,
        aw,
        132,
        [
            ln("A person or", "tx", 14, True),
            ln("an AI coding agent", "tx", 14, True),
            ln("edits a security group,", "mu", 12),
            ln("S3 or IAM policy", "mu", 12),
        ],
    )

    bx, bw = 268, 236
    entries = [
        ("Claude Code hook", "after every .tf edit"),
        ("MCP tool: check_change", "Cursor, Codex, Copilot, Gemini…"),
        ("CI check on the PR", "GitHub Action or any CI"),
    ]
    for y, (name, sub) in zip(ys, entries, strict=True):
        d.box(bx, y - bh / 2, bw, bh, [ln(name, "tx", 13.5, True), ln(sub, "mu", 12)])
        d.arrow([(ax + aw, mid), (bx - 22, mid), (bx - 22, y), (bx - 2, y)])

    cx, cw = 548, 236
    d.box(
        cx,
        mid - 80,
        cw,
        160,
        [
            ln("posturanet", "tx", 15, True, True),
            ln("contract check", "tx", 15, True, True),
            ln("the edited HCL or the plan", "mu", 12),
            ln("vs posturanet/contracts/", "mu", 12, mono=True),
            ln("network · s3_public · iam", "acc", 12),
        ],
        edge="acc",
        width=1.75,
    )
    for y in ys:
        d.arrow([(bx + bw, y), (cx - 22, y), (cx - 22, mid), (cx - 2, mid)])

    ox, ow = 828, 208
    outcomes = [
        ("PASS", "ok", "every contract line kept"),
        ("UNKNOWN · exit 3", "warn", "can't judge: rerun with a plan"),
        ("BLOCK · exit 5", "crit", "breaks a contract line"),
    ]
    d.arrow([(cx + cw, mid), (ox - 22, mid)], head=False)
    d.arrow([(ox - 22, ys[0]), (ox - 22, ys[2])], head=False)
    for y, (word, tone, sub) in zip(ys, outcomes, strict=True):
        d.box(
            ox,
            y - bh / 2,
            ow,
            bh,
            [ln(word, tone, 14, True, True), ln(sub, "mu", 12)],
            edge=tone,
            fill="bg",
            width=1.75,
        )
        d.arrow([(ox - 22, y), (ox - 2, y)], tone)

    # BLOCK goes back to whoever made the change.
    yb = ys[2] + bh / 2
    y_loop = 356
    d.arrow(
        [(ox + ow / 2, yb), (ox + ow / 2, y_loop), (ax + aw / 2, y_loop), (ax + aw / 2, mid + 68)],
        "crit",
        dash=True,
    )
    d.parts.append(f'<rect x="364" y="{y_loop - 11}" width="332" height="22" class="f-bg"/>')
    d.text(530, y_loop + 4, "told which line it broke, so it fixes its own change", "crit", 12.5)
    return d


def trust_boundary() -> Diagram:
    """What runs where: everything inside your environment, nothing sent out."""
    d = Diagram(1060, 420, "Where PosturaNet runs and what leaves your environment")
    d.box(24, 20, 1012, 300, [], edge="bds", fill="bg", dash=True)
    d.text(
        44,
        46,
        "YOUR ENVIRONMENT: your cloud account, your CI, your GitHub",
        "mu",
        11.5,
        True,
        anchor="start",
    )

    ix, iw, ih = 52, 236, 48
    inputs = [
        ("Security Hub", "the finding (ASFF)"),
        ("Terraform repo", "code, owners, state"),
        ("read-only AWS role", "flow logs, CloudTrail, IAM usage"),
        ("your LLM (optional)", "Bedrock or your own key"),
    ]
    iys = [72 + i * 60 for i in range(4)]
    mid = 72 + 3 * 60 / 2 + ih / 2

    cx, cw, ch = 388, 284, 156
    for y, (name, sub) in zip(iys, inputs, strict=True):
        d.box(ix, y, iw, ih, [ln(name, "tx", 13, True), ln(sub, "mu", 11.5)])
        d.arrow([(ix + iw, y + ih / 2), (cx - 24, y + ih / 2), (cx - 24, mid), (cx - 2, mid)])

    d.box(
        cx,
        mid - ch / 2,
        cw,
        ch,
        [
            ln("PosturaNet agent", "tx", 15, True),
            ln("in your CI or on a laptop", "mu", 12),
            ln("", "mu", 6),
            ln("no writes to production", "ok", 12, True),
            ln("the LLM explains; code decides", "mu", 12),
        ],
        edge="acc",
        width=1.75,
    )

    ox, ow, oh = 772, 236, 56
    outs = [
        ("GitHub pull request", "plus a check run; you merge"),
        ("run record", "evidence files in the repo"),
    ]
    oys = [mid - 70, mid + 14]
    for y, (name, sub) in zip(oys, outs, strict=True):
        d.box(ox, y, ow, oh, [ln(name, "tx", 13, True), ln(sub, "mu", 11.5)])
        d.arrow([(cx + cw, mid), (ox - 24, mid), (ox - 24, y + oh / 2), (ox - 2, y + oh / 2)])

    ly = 352
    d.box(
        cx,
        ly,
        cw,
        50,
        [
            ln("PosturaNet license service", "tx", 13, True),
            ln("keys are checked offline", "mu", 11.5),
        ],
        edge="bds",
    )
    d.arrow([(cx + cw / 2, mid + ch / 2), (cx + cw / 2, ly - 2)], "mu", dash=True)
    d.text(
        cx + cw / 2 + 12,
        338,
        "optional heartbeat: license id + version only",
        "mu",
        11.5,
        anchor="start",
    )
    return d


DIAGRAMS: dict[str, Callable[[], Diagram]] = {
    "diagram-pipeline": pipeline,
    "diagram-change-check": change_gate,
    "diagram-trust": trust_boundary,
}


def main() -> None:
    for name, make in DIAGRAMS.items():
        (OUT / f"{name}.svg").write_text(make().render(), encoding="utf-8", newline="\n")
        print(f"wrote docs/media/{name}.svg")


if __name__ == "__main__":
    main()
