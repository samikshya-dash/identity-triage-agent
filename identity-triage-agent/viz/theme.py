"""Two themes for every graphic. GitHub shows the light file to light-mode readers and the dark
file to dark-mode readers through a <picture> tag in the README."""
THEMES = {
    "light": dict(bg="#fcfcfb", card="#ffffff", border="#dcdbd4", ink="#0b0b0b", ink2="#52514e", muted="#6f6e69", grid="#e7e6df", axis="#c3c2b7",
                  blue="#2a78d6", orange="#eb6834", aqua="#1baf7a", violet="#4a3aa7", red="#e34948", yellow="#b87a00",
                  tint=0.10, on_fill="#ffffff", chip="#f3f2ee"),
    "dark": dict(bg="#0b1b33", card="#10233f", border="#2a4f80", ink="#ffffff", ink2="#cfe3ff", muted="#8fb3dd", grid="#24406a", axis="#3b5b8a",
                 blue="#3987e5", orange="#d95926", aqua="#199e70", violet="#9085e9", red="#e66767", yellow="#c98500",
                 tint=0.22, on_fill="#ffffff", chip="#173459"),
}
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}   # fixed in both themes
FONT = "system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "ui-monospace,Menlo,Consolas,monospace"


def esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;")


def wrap(text, n):
    words, lines, cur = str(text).split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > n and cur:
            lines.append(cur); cur = w
        else:
            cur = (cur + " " + w).strip()
    return lines + [cur] if cur else lines


def frame(T, w, h, title, subtitle="", label=None):
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="{esc(label or title)}">',
         f"<style>text{{font-family:{FONT}}}</style>",
         f'<rect x="0.5" y="0.5" width="{w-1}" height="{h-1}" rx="12" fill="{T["bg"]}" stroke="{T["border"]}"/>']
    if title:
        s.append(f'<text x="24" y="36" font-size="17" font-weight="700" fill="{T["ink"]}">{esc(title)}</text>')
    if subtitle:
        s.append(f'<text x="24" y="58" font-size="12.5" fill="{T["muted"]}">{esc(subtitle)}</text>')
    return s


def both(fn, stem, *args, **kw):
    """Write <stem>-light.svg and <stem>-dark.svg."""
    for name, T in THEMES.items():
        open(f"{stem}-{name}.svg", "w").write("\n".join(fn(T, *args, **kw)))
