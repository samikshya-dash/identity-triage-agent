"""README graphics: banner, cards, architecture, triage flow, detection map and control matrix.
Every function takes a theme and returns SVG lines; theme.both() writes the light and dark files."""
from .theme import MONO, STATUS, esc, frame, wrap

PRIORITY_COLOR = {"P1": "red", "P2": "orange", "P3": "blue", "P4": "muted"}


def _marker(T):
    return (f'<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{T["muted"]}"/></marker></defs>')


def _arrow(T, s, x1, y1, x2, y2, label=None, lx=None, ly=None, anchor="middle"):
    s.append(f'<path d="M{x1},{y1} L{x2},{y2}" stroke="{T["muted"]}" stroke-width="1.7" fill="none" marker-end="url(#ar)"/>')
    if label:
        s.append(f'<text x="{lx if lx is not None else (x1+x2)/2}" y="{ly if ly is not None else (y1+y2)/2-7}" font-size="11.8" fill="{T["muted"]}" text-anchor="{anchor}">{esc(label)}</text>')


def _box(T, s, x, y, w, h, color, title, lines, size=12.2):
    c = T[color]
    s.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{T["card"]}"/>')
    s.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{c}" fill-opacity="{T["tint"]}" stroke="{c}" stroke-width="1.5"/>')
    s.append(f'<text x="{x+w/2}" y="{y+28}" font-size="15" font-weight="700" fill="{T["ink"]}" text-anchor="middle">{esc(title)}</text>')
    for i, l in enumerate(lines):
        s.append(f'<text x="{x+w/2}" y="{y+50+i*17}" font-size="{size}" fill="{T["ink2"]}" text-anchor="middle">{esc(l)}</text>')


def _pill(T, s, x, y, w, text, color, h=32):
    c = STATUS.get(color) or T[color]
    s.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h/2}" fill="{c}" fill-opacity="{T["tint"]+0.06}" stroke="{c}" stroke-width="1.3"/>'
             f'<text x="{x+w/2}" y="{y+h/2+4.5}" font-size="12.5" font-weight="600" fill="{T["ink"]}" text-anchor="middle">{esc(text)}</text>')


def banner(T, title, subtitle, chips, accent="violet"):
    W, H = 1000, 210
    s = frame(T, W, H, "", label=title)
    a = T[accent]
    s += [f'<rect x="0.5" y="0.5" width="8" height="{H-1}" rx="4" fill="{a}"/>',
          f'<text x="44" y="78" font-size="34" font-weight="700" fill="{T["ink"]}">{esc(title)}</text>',
          f'<rect x="44" y="94" width="120" height="4" rx="2" fill="{a}"/>',
          f'<text x="44" y="130" font-size="16.5" fill="{T["ink2"]}">{esc(subtitle)}</text>']
    x = 44
    for n, l in chips:
        w = len(l) * 7.4 + len(n) * 12 + 44
        s.append(f'<rect x="{x:.0f}" y="154" width="{w:.0f}" height="34" rx="17" fill="{T["chip"]}" stroke="{T["border"]}"/>'
                 f'<text x="{x+16:.0f}" y="177" font-size="16" font-weight="700" fill="{a}">{esc(n)}</text>'
                 f'<text x="{x+24+len(n)*10.5:.0f}" y="177" font-size="13.5" fill="{T["ink2"]}">{esc(l)}</text>')
        x += w + 12
    return s + ["</svg>"]


def cards(T, title, subtitle, items, cols=3, ch=180):
    """items: (badge, heading, [lines], footer, color key)."""
    W, gx, gy, x0, y0 = 1000, 20, 20, 24, 80
    cw = (W - 2 * x0 - (cols - 1) * gx) / cols
    rows = -(-len(items) // cols)
    H = y0 + rows * ch + (rows - 1) * gy + 24
    s = frame(T, W, H, title, subtitle)
    for i, (badge, head, lines, foot, color) in enumerate(items):
        x, y, c = x0 + (i % cols) * (cw + gx), y0 + (i // cols) * (ch + gy), T[color]
        s.append(f'<rect x="{x:.1f}" y="{y}" width="{cw:.1f}" height="{ch}" rx="10" fill="{T["card"]}" stroke="{T["border"]}"/>'
                 f'<rect x="{x:.1f}" y="{y}" width="{cw:.1f}" height="4" rx="2" fill="{c}"/>')
        tx = x + 20
        if badge:
            s.append(f'<circle cx="{x+30:.1f}" cy="{y+36}" r="15" fill="{c}"/><text x="{x+30:.1f}" y="{y+41.5}" font-size="15" font-weight="700" fill="#fff" text-anchor="middle">{esc(badge)}</text>')
            tx = x + 56
        hl = wrap(head, max(8, int((x + cw - tx - 12) / 8.6)))
        for j, h in enumerate(hl):
            s.append(f'<text x="{tx:.1f}" y="{y+(41 if len(hl)==1 else 32)+j*18}" font-size="15.5" font-weight="700" fill="{T["ink"]}">{esc(h)}</text>')
        ly = y + 76
        for raw in lines:
            for ln in wrap(raw, int((cw - 36) / 6.7)):
                s.append(f'<text x="{x+20:.1f}" y="{ly}" font-size="12.5" fill="{T["ink2"]}">{esc(ln)}</text>'); ly += 19
        if foot:
            fw = len(foot) * 6.9 + 24
            s.append(f'<rect x="{x+20:.1f}" y="{y+ch-36}" width="{fw:.0f}" height="24" rx="12" fill="{c}" fill-opacity="{T["tint"]+0.05}"/>'
                     f'<text x="{x+32:.1f}" y="{y+ch-19.5}" font-size="11.5" font-weight="600" fill="{T["ink"]}" font-family="{MONO}">{esc(foot)}</text>')
    return s + ["</svg>"]


def architecture(T):
    W, H = 1000, 640
    s = frame(T, W, H, "The model proposes, code decides",
              "Code closes what is already resolved, the brain investigates the rest, and code checks every action and verdict before it stands.")
    s.append(_marker(T))
    _pill(T, s, 40, 100, 150, "Risk detection", "blue")
    _box(T, s, 250, 84, 300, 64, "orange", "Pre-triage", ["Already closed? Do the logs agree?"])
    _pill(T, s, 690, 100, 270, "Auto-closed, no model call", "violet")
    _arrow(T, s, 190, 116, 246, 116)
    _arrow(T, s, 550, 116, 686, 116, "closed and consistent")
    _arrow(T, s, 500, 148, 500, 216, "open, or reopened", lx=510, ly=188, anchor="start")
    _box(T, s, 40, 220, 240, 112, "violet", "Brain", ["Language model, or offline rules", "Chooses the next step", "Cannot execute anything"])
    _box(T, s, 380, 220, 240, 112, "blue", "Agent loop", ["Step budget · tool allow-list", "Audit trail of every call", "Runs the guardrails"])
    _box(T, s, 720, 220, 240, 112, "blue", "11 read-only tools", ["Sign-ins · profile · audit · device · IP", "Risk history · detection playbook", "Conditional Access review"])
    _arrow(T, s, 380, 256, 284, 256, "history so far")
    _arrow(T, s, 280, 298, 376, 298, "next tool calls", ly=316)
    _arrow(T, s, 620, 256, 716, 256, "tool call")
    _arrow(T, s, 720, 298, 624, 298, "facts, as data", ly=316)
    _box(T, s, 215, 415, 260, 100, "orange", "Action policy", ["Scope lock · approval rules", "Break-glass accounts never touched"])
    _box(T, s, 525, 415, 260, 100, "orange", "Verifier", ["Evidence must cite real tool calls", "A contradicted 'benign' is overruled"])
    _arrow(T, s, 450, 332, 360, 411, "propose_action", lx=372, ly=370, anchor="end")
    _arrow(T, s, 550, 332, 640, 411, "submit_verdict", lx=628, ly=370, anchor="start")
    for x, w, t, c, ax in [(40, 170, "Runs automatically", "good", 290), (230, 170, "Waits for a person", "warning", 345), (420, 100, "Denied", "critical", 400)]:
        _pill(T, s, x, 570, w, t, c)
        _arrow(T, s, ax, 515, x + w / 2, 566)
    _pill(T, s, 560, 570, 190, "Verdict and evidence", "good")
    _arrow(T, s, 655, 515, 655, 566)
    _pill(T, s, 790, 570, 170, "Prevention gaps", "blue")
    _arrow(T, s, 880, 332, 878, 566)
    return s + ["</svg>"]


def triage_flow(T):
    W, H = 1000, 470
    s = frame(T, W, H, "Triage starts with the risk state",
              "ID Protection has often resolved the risk already. The agent closes those in code, after checking that the logs agree.")
    s.append(_marker(T))
    rows = [("remediated, dismissed, confirmed safe", "violet",
             ("Safety check in code", ["No account change from the unfamiliar IP", "MFA is enough for this detection type", "A leaked password was actually changed"]),
             [("Auto-close: all checks hold", "good", ""), ("Reopen: any check fails", "critical", "")]),
            ("at risk", "orange",
             ("Set priority, then investigate", ["P1 to P4 from detection type, risk level", "and whether the account is privileged", "Agent gathers facts with its tools"]),
             [("Attack: propose containment", "critical", ""), ("Benign or unclear: a person", "good", "")]),
            ("confirmed compromised", "red",
             ("Scope the damage", ["An administrator has already decided", "Agent finds what the attacker changed", "and proposes how to undo each change"]),
             [("Containment plan for approval", "critical", "")])]
    y = 86
    for state, color, (title, lines), outs in rows:
        _pill(T, s, 24, y + 34, 300, state, color, h=36)
        _box(T, s, 380, y, 290, 104, color, title, lines, size=11.8)
        _arrow(T, s, 324, y + 52, 376, y + 52)
        oy = y + (52 - 18 if len(outs) == 1 else 8)
        for text, c, label in outs:
            _pill(T, s, 720, oy, 256, text, c, h=36)
            _arrow(T, s, 670, y + 52, 716, oy + 18)
            if label:
                s.append(f'<text x="{848}" y="{oy+50}" font-size="11" fill="{T["muted"]}" text-anchor="middle">{esc(label)}</text>')
            oy += 54
        y += 124
    return s + ["</svg>"]


def detection_map(T, detections, priority_of):
    """All detection types as tiles: colour bar = starting priority, tags = scope, timing, and whether MFA is enough."""
    cols, tw, th, gx, gy, x0, y0 = 4, 228, 66, 13, 10, 24, 112
    items = sorted(detections.items(), key=lambda kv: (kv[1]["scope"] == "user", kv[1]["priority"], kv[1]["name"]))
    rows = -(-len(items) // cols)
    W, H = 1000, y0 + rows * (th + gy) + 14
    s = frame(T, W, H, f"The {len(items)} ID Protection risk detections the agent knows",
              "Colour bar: starting priority before investigation. A lock means passing MFA does not clear the risk, so the agent never auto-closes it on MFA alone.")
    lx = 24
    for label, c in [("P1 start", "red"), ("P2 start", "orange"), ("P3 start", "blue")]:
        s.append(f'<rect x="{lx}" y="76" width="14" height="14" rx="3" fill="{T[c]}"/><text x="{lx+20}" y="88" font-size="12" fill="{T["ink2"]}">{label}</text>')
        lx += 96
    s.append(f'<text x="{lx+10}" y="88" font-size="12" fill="{T["ink2"]}">🔒 MFA is not enough   ·   S sign-in risk   U user risk   ·   RT real-time   OFF offline</text>')
    for i, (key, d) in enumerate(items):
        x, y, c = x0 + (i % cols) * (tw + gx), y0 + (i // cols) * (th + gy), T[PRIORITY_COLOR[d["priority"]]]
        s.append(f'<rect x="{x}" y="{y}" width="{tw}" height="{th}" rx="8" fill="{T["card"]}" stroke="{T["border"]}"/><rect x="{x}" y="{y}" width="5" height="{th}" rx="2.5" fill="{c}"/>')
        for j, ln in enumerate(wrap(d["name"], 27)[:2]):
            s.append(f'<text x="{x+16}" y="{y+22+j*16}" font-size="12.6" font-weight="700" fill="{T["ink"]}">{esc(ln)}</text>')
        scope = {"sign-in": "S", "user": "U", "both": "S+U"}[d["scope"]]
        timing = {"real-time": "RT", "offline": "OFF"}.get(d["timing"], "RT/OFF")
        tags = f"{scope} · {timing}" + ("" if d["mfa_clears"] else " · 🔒")
        s.append(f'<text x="{x+16}" y="{y+th-10}" font-size="11" fill="{T["muted"]}">{tags}</text>')
    return s + ["</svg>"]


def control_matrix(T, rows, controls, relevant, status):
    """rows: [(key, name)] detections; controls: [(id, name, kind)]; relevant(key, id) -> bool; status[id] -> 'ok' or 'gap'."""
    lw, cw, rh, x0, top = 266, 34, 30, 24, 236
    W, H = 1000, top + len(rows) * rh + 54
    s = frame(T, W, H, "Which Conditional Access policy matters for which detection",
              "A mark means the agent checks that control after that kind of alert. Filled: in place in the sample tenant. Hollow, orange heading: a gap it reports.")
    for j, (cid, name, kind) in enumerate(controls):
        cx = x0 + lw + j * cw + cw / 2
        col = T["ink2"] if status[cid] == "ok" else T["orange"]
        s.append(f'<text transform="translate({cx+4:.1f},{top-12}) rotate(-55)" font-size="11.8" fill="{col}" font-weight="{600 if status[cid] != "ok" else 400}">{esc(name)}</text>')
        s.append(f'<line x1="{cx:.1f}" x2="{cx:.1f}" y1="{top-4}" y2="{top+len(rows)*rh}" stroke="{T["grid"]}"/>')
    for i, (key, name) in enumerate(rows):
        y = top + i * rh
        if i % 2 == 0:
            s.append(f'<rect x="{x0}" y="{y}" width="{W-2*x0}" height="{rh}" fill="{T["ink"]}" fill-opacity="0.035"/>')
        s.append(f'<text x="{x0+8}" y="{y+19.5}" font-size="12.3" fill="{T["ink"]}">{esc(name)}</text>')
        for j, (cid, _n, _k) in enumerate(controls):
            if relevant(key, cid):
                cx, cy = x0 + lw + j * cw + cw / 2, y + rh / 2
                if status[cid] == "ok":
                    s.append(f'<circle cx="{cx:.1f}" cy="{cy}" r="6.5" fill="{T["aqua"]}"><title>{esc(name)} · {esc(_n)}: in place</title></circle>')
                else:
                    s.append(f'<circle cx="{cx:.1f}" cy="{cy}" r="5.6" fill="{T["bg"]}" stroke="{T["orange"]}" stroke-width="2.6"><title>{esc(name)} · {esc(_n)}: gap</title></circle>')
    ly = top + len(rows) * rh + 30
    s.append(f'<circle cx="{x0+14}" cy="{ly-4}" r="6.5" fill="{T["aqua"]}"/><text x="{x0+28}" y="{ly}" font-size="12" fill="{T["ink2"]}">in place</text>')
    s.append(f'<circle cx="{x0+110}" cy="{ly-4}" r="5.6" fill="{T["bg"]}" stroke="{T["orange"]}" stroke-width="2.6"/><text x="{x0+124}" y="{ly}" font-size="12" fill="{T["ink2"]}">gap in the sample tenant: missing, report-only, or not covering every app</text>')
    return s + ["</svg>"]
