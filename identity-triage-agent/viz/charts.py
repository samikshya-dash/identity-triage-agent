"""Small dependency-free SVG charts, each drawn in a light and a dark theme."""
import math

from .theme import STATUS, esc, frame


def _scale(v):
    """(top, step): whole-number gridlines, at most five steps."""
    v = max(v, 1)
    e = 10 ** math.floor(math.log10(v))
    for step in (e / 10, e / 5, e / 2, e, 2 * e, 5 * e, 10 * e):
        if step >= 1 and math.ceil(v / step) <= 5:
            return step * math.ceil(v / step), step
    return v, v


def _color(T, c):
    return STATUS.get(c) or T.get(c) or c


def _axis(T, s, L, R, Tp, ph, w, top, step, unit):
    v = 0
    while v <= top + 1e-9:
        y = Tp + ph - ph * v / top
        s.append(f'<line x1="{L}" x2="{w-R}" y1="{y:.1f}" y2="{y:.1f}" stroke="{T["axis"] if v == 0 else T["grid"]}"/>')
        s.append(f'<text x="{L-8}" y="{y+4:.1f}" font-size="11" fill="{T["muted"]}" text-anchor="end">{v:,.0f}{unit}</text>')
        v += step


def _legend(T, s, w, R, items):
    lx = w - R
    for name, c in reversed(items):
        lx -= 7.8 * len(name) + 30
        s.append(f'<rect x="{lx}" y="25" width="12" height="12" rx="3" fill="{_color(T, c)}"/><text x="{lx+17}" y="35.5" font-size="12" fill="{T["ink2"]}">{esc(name)}</text>')


def _bar(x, y, bw, base, col, tip):
    r = min(4, max(0, (base - y) / 2))
    return (f'<path d="M{x:.1f},{base:.1f} V{y+r:.1f} Q{x:.1f},{y:.1f} {x+r:.1f},{y:.1f} H{x+bw-r:.1f} Q{x+bw:.1f},{y:.1f} {x+bw:.1f},{y+r:.1f} V{base:.1f} Z" '
            f'fill="{col}"><title>{esc(tip)}</title></path>')


def bars(T, title, subtitle, labels, values, colors, unit="", w=860, h=340, legend=None):
    s = frame(T, w, h, title, subtitle)
    L, R, Tp, B = 56, 24, 88, 52
    pw, ph = w - L - R, h - Tp - B
    top, step = _scale(max(values) * 1.05)
    _axis(T, s, L, R, Tp, ph, w, top, step, unit)
    if legend:
        _legend(T, s, w, R, legend)
    slot = pw / len(values)
    bw = min(64, slot * 0.6)
    for i, (lab, v, c) in enumerate(zip(labels, values, colors)):
        x, y = L + slot * i + (slot - bw) / 2, Tp + ph - ph * v / top
        s.append(_bar(x, y, bw, Tp + ph, _color(T, c), f"{lab}: {v:,}{unit}"))
        s.append(f'<text x="{x+bw/2:.1f}" y="{y-6:.1f}" font-size="12" font-weight="700" fill="{T["ink"]}" text-anchor="middle">{v:,}{unit}</text>')
        for j, ln in enumerate(str(lab).split("\n")):
            s.append(f'<text x="{x+bw/2:.1f}" y="{Tp+ph+18+j*14:.1f}" font-size="11.5" fill="{T["ink2"]}" text-anchor="middle">{esc(ln)}</text>')
    return s + ["</svg>"]


def grouped(T, title, subtitle, labels, series, unit="", w=860, h=360):
    """series: [(name, color key, values)]. Legend top right, a value on every bar."""
    s = frame(T, w, h, title, subtitle)
    L, R, Tp, B = 56, 24, 98, 52
    pw, ph = w - L - R, h - Tp - B
    top, step = _scale(max(max(v) for _, _, v in series) * 1.05)
    _axis(T, s, L, R, Tp, ph, w, top, step, unit)
    _legend(T, s, w, R, [(n, c) for n, c, _ in series])
    k, slot = len(series), pw / len(labels)
    bw = min(36, slot * 0.7 / k)
    for i, lab in enumerate(labels):
        x0 = L + slot * i + (slot - bw * k - 2 * (k - 1)) / 2
        for j, (name, c, vals) in enumerate(series):
            x, y = x0 + j * (bw + 2), Tp + ph - ph * vals[i] / top
            s.append(_bar(x, y, bw, Tp + ph, _color(T, c), f"{lab} · {name}: {vals[i]:,}{unit}"))
            s.append(f'<text x="{x+bw/2:.1f}" y="{y-5:.1f}" font-size="11" font-weight="700" fill="{T["ink"]}" text-anchor="middle">{vals[i]:,}{unit}</text>')
        s.append(f'<text x="{L+slot*i+slot/2:.1f}" y="{Tp+ph+18:.1f}" font-size="11.5" fill="{T["ink2"]}" text-anchor="middle">{esc(lab)}</text>')
    return s + ["</svg>"]


def hbars(T, title, subtitle, labels, values, color="blue", unit="", w=860, row=34, label_w=260, notes=None):
    h = 84 + row * len(values) + 18
    s = frame(T, w, h, title, subtitle)
    L, R, Tp = label_w, 90 if notes is None else 250, 78
    pw, top = w - L - R, max(values)
    for i, (lab, v) in enumerate(zip(labels, values)):
        y, bw = Tp + i * row, max(4, pw * v / top)
        col = _color(T, color[i] if isinstance(color, list) else color)
        s.append(f'<text x="{L-10}" y="{y+18}" font-size="12.5" fill="{T["ink2"]}" text-anchor="end">{esc(lab)}</text>')
        s.append(f'<rect x="{L}" y="{y+5}" width="{bw:.1f}" height="{row-13}" rx="4" fill="{col}"><title>{esc(lab)}: {v:,}{unit}</title></rect>')
        s.append(f'<text x="{L+bw+8:.1f}" y="{y+18}" font-size="12.5" font-weight="700" fill="{T["ink"]}">{v:,}{unit}</text>')
        if notes:
            s.append(f'<text x="{L+bw+30:.1f}" y="{y+18}" font-size="11.5" fill="{T["muted"]}">{esc(notes[i])}</text>')
    return s + ["</svg>"]


def stacked_row(T, title, subtitle, parts, w=860, h=178):
    """One horizontal bar split into parts: [(label, value, color key)], with a labelled key underneath."""
    s = frame(T, w, h, title, subtitle)
    L, R, y, bh = 24, 24, 80, 40
    total, x = sum(v for _, v, _ in parts), L
    pw = w - L - R - 2 * (len(parts) - 1)
    for label, v, c in parts:
        bw = pw * v / total
        s.append(f'<rect x="{x:.1f}" y="{y}" width="{bw:.1f}" height="{bh}" rx="5" fill="{_color(T, c)}"><title>{esc(label)}: {v}</title></rect>')
        s.append(f'<text x="{x+bw/2:.1f}" y="{y+26}" font-size="16" font-weight="700" fill="{T["on_fill"]}" text-anchor="middle">{v}</text>')
        x += bw + 2
    kx = L
    for label, v, c in parts:
        s.append(f'<rect x="{kx}" y="{y+bh+18}" width="12" height="12" rx="3" fill="{_color(T, c)}"/>'
                 f'<text x="{kx+18}" y="{y+bh+28.5}" font-size="12.5" fill="{T["ink2"]}"><tspan font-weight="700" fill="{T["ink"]}">{v}</tspan>  {esc(label)}</text>')
        kx += 7.0 * (len(label) + len(str(v))) + 40
    return s + ["</svg>"]
