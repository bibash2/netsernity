#!/usr/bin/env python3
"""Regenerate every report figure in docs/figures at true print size.

Each figure is laid out in inches at the width it occupies on the A4 page
(6.0 in between the report margins) and rendered at 300 dpi, so an 8 pt label
here prints as 8 pt in Word: no more shrinking a 2800 px diagram to 6 in.

    python docs/figures/make_figures.py            # all figures
    python docs/figures/make_figures.py arch class # selected figures
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import Circle, Ellipse, FancyArrowPatch, FancyBboxPatch, Polygon, Rectangle  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
DPI = 300
W = 6.0  # printable width in inches
plt.rcParams.update({"font.family": "Times New Roman", "font.size": 9, "text.color": "#000000", "axes.labelcolor": "#000000", "xtick.color": "#000000", "ytick.color": "#000000", "axes.edgecolor": "#000000"})
FS_MIN = 7.0  # nothing smaller than 7 pt on paper

INK, LINE, MUTED = "#000000", "#111111", "#2b2b2b"   # print-safe: black text, no faded greys
C = {  # black and white only: white fill, black outline
    k: ("#ffffff", "#000000") for k in ("blue", "indigo", "purple", "green", "orange", "red", "grey", "yellow", "white", "teal")
}
LH = lambda fs: fs / 72 * 1.45  # line height in inches for a font size in points


# ── drawing helpers ─────────────────────────────────────────────────────────
def canvas(h):
    fig = plt.figure(figsize=(W, h))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W); ax.set_ylim(0, h); ax.axis("off")
    return fig, ax


def save(fig, name, pad_in=0.06):
    """Enforce the print minimum font size, save at 300 dpi, then trim the white
    border (keeping `pad_in` inches) so the drawing fills its embed width."""
    import matplotlib.text
    for txt in fig.findobj(matplotlib.text.Text):
        if txt.get_fontsize() < FS_MIN:
            txt.set_fontsize(FS_MIN)
    out = OUT / name
    fig.savefig(out, dpi=DPI, facecolor="white")
    plt.close(fig)
    from PIL import Image, ImageChops
    im = Image.open(out).convert("RGB")
    bbox = ImageChops.difference(im, Image.new("RGB", im.size, (255, 255, 255))).convert("L").point(lambda v: 255 if v > 8 else 0).getbbox()
    if bbox:
        pad = int(pad_in * DPI)
        l, t, r, b = bbox
        im.crop((max(0, l - pad), max(0, t - pad), min(im.width, r + pad), min(im.height, b + pad))).save(out, dpi=(DPI, DPI))
    print("wrote", name)


def bh(n_lines, ts=8.5, bs=7.0, title=True):
    """Box height for a title plus n body lines."""
    return 0.1 + (LH(ts) if title else 0) + n_lines * LH(bs) + 0.1


def box(ax, x, y, w, h, title=None, lines=(), color="white", ts=8.5, bs=7.0, r=0.06, lw=1.3, ls="-", tc=None):
    fc, ec = C[color]
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}", fc=fc, ec=ec, lw=lw, ls=ls))
    cx = x + w / 2
    if title and not lines:
        ax.text(cx, y + h / 2, title, ha="center", va="center", fontsize=ts, fontweight="bold", color=tc or INK)
    elif title:
        ax.text(cx, y + h - 0.1, title, ha="center", va="top", fontsize=ts, fontweight="bold", color=tc or INK)
        top = y + h - 0.1 - LH(ts)
        for i, ln in enumerate(lines):
            ax.text(cx, top - i * LH(bs), ln, ha="center", va="top", fontsize=bs, color=LINE)
    else:
        top = y + h / 2 + (len(lines) - 1) / 2 * LH(bs)
        for i, ln in enumerate(lines):
            ax.text(cx, top - i * LH(bs), ln, ha="center", va="center", fontsize=bs, color=LINE)
    return x, y, w, h


def label(ax, x, y, text, fs=6.8, color=LINE, bold=False, ha="center", va="center", pad=0.12, bg="white"):
    ax.text(x, y, text, ha=ha, va=va, fontsize=fs, color=color, fontweight="bold" if bold else "normal",
            bbox=dict(boxstyle=f"round,pad={pad}", fc=bg, ec="none") if bg else None)


def arrow(ax, p, q, color=LINE, ls="-", lw=1.2, style="-|>", ms=9, rad=0.0, hollow=False, text=None, tpos=0.5, toff=(0, 0.08), fs=6.8):
    a = FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=ms, lw=lw, ec=color,
                        fc="white" if hollow else color, ls=ls, connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0)
    ax.add_patch(a)
    if text:
        label(ax, p[0] + (q[0] - p[0]) * tpos + toff[0], p[1] + (q[1] - p[1]) * tpos + toff[1], text, fs=fs)


def path(ax, pts, color=LINE, ls="-", lw=1.2, head=True, ms=9, hollow=False, text=None, tpt=None, fs=6.8):
    xs, ys = zip(*pts)
    n = len(pts) - 1 if head else len(pts)
    ax.plot(xs[:n], ys[:n], color=color, ls=ls, lw=lw, solid_capstyle="round")
    if head:
        arrow(ax, pts[-2], pts[-1], color=color, ls=ls, lw=lw, ms=ms, hollow=hollow)
    if text and tpt:
        label(ax, tpt[0], tpt[1], text, fs=fs)


def group(ax, x, y, w, h, title, color, fs=8.2):
    _, ec = C[color]
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.1", fc="#ffffff", ec=ec, lw=1.0, ls=(0, (4, 3))))
    ax.text(x + 0.12, y + h - 0.06, title, ha="left", va="top", fontsize=fs, fontweight="bold", color=ec)


def actor(ax, x, y, text, fs=8):
    """Stick figure standing on y; total height ~0.6 in; label below the feet."""
    ax.add_patch(Circle((x, y + 0.5), 0.075, fc="white", ec=INK, lw=1.2))
    ax.plot([x, x], [y + 0.425, y + 0.18], color=INK, lw=1.2)
    ax.plot([x - 0.14, x + 0.14], [y + 0.36, y + 0.36], color=INK, lw=1.2)
    ax.plot([x, x - 0.12], [y + 0.18, y], color=INK, lw=1.2)
    ax.plot([x, x + 0.12], [y + 0.18, y], color=INK, lw=1.2)
    ax.text(x, y - 0.07, text, ha="center", va="top", fontsize=fs, fontweight="bold", linespacing=1.1)


def usecase(ax, x, y, text, w=1.32, h=0.48, fs=7.2):
    ax.add_patch(Ellipse((x, y), w, h, fc="white", ec=INK, lw=1.0))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, linespacing=1.15)


def klass(ax, x, y_top, w, title, attrs=(), methods=(), color="indigo", ts=7.8, bs=6.4, stereo=None):
    lh = LH(bs)
    head = 0.21 + (0.1 if stereo else 0)
    ah = len(attrs) * lh + (0.07 if attrs else 0)
    mh = len(methods) * lh + (0.07 if methods else 0)
    h = head + ah + mh + 0.02
    y = y_top - h
    fc, ec = C[color]
    ax.add_patch(Rectangle((x, y), w, h, fc="white", ec=ec, lw=1.0))
    ax.add_patch(Rectangle((x, y_top - head), w, head, fc=fc, ec=ec, lw=1.0))
    if stereo:
        ax.text(x + w / 2, y_top - 0.025, stereo, ha="center", va="top", fontsize=bs - 0.6, color=LINE, style="italic")
    ax.text(x + w / 2, y_top - head / 2 - (0.045 if stereo else 0), title, ha="center", va="center", fontsize=ts, fontweight="bold")
    yy = y_top - head
    if attrs:
        for i, t in enumerate(attrs):
            ax.text(x + 0.06, yy - 0.04 - i * lh, t, ha="left", va="top", fontsize=bs, color=LINE)
        yy -= ah
        ax.plot([x, x + w], [yy, yy], color=ec, lw=0.8)
    for i, t in enumerate(methods):
        ax.text(x + 0.06, yy - 0.04 - i * lh, t, ha="left", va="top", fontsize=bs, color=LINE)
    return dict(x=x, y=y, w=w, h=h, cx=x + w / 2, top=y_top, bottom=y, left=x, right=x + w)


def diamond(ax, x, y, w, h, text, fs=6.9):
    fc, ec = C["yellow"]
    ax.add_patch(Polygon([(x - w / 2, y), (x, y + h / 2), (x + w / 2, y), (x, y - h / 2)], closed=True, fc=fc, ec=ec, lw=1.0))
    ax.text(x, y, text, ha="center", va="center", fontsize=fs, linespacing=1.15)


def terminal(ax, x, y, end=False):
    ax.add_patch(Circle((x, y), 0.085, fc=INK, ec=INK))
    if end:
        ax.add_patch(Circle((x, y), 0.125, fc="none", ec=INK, lw=1.4))


def node3d(ax, x, y, w, h, title, lines=(), color="grey", d=0.08, ts=7.8, bs=6.6, stereo=None):
    fc, ec = C[color]
    ax.add_patch(Polygon([(x, y + h), (x + d, y + h + d), (x + w + d, y + h + d), (x + w, y + h)], fc=fc, ec=ec, lw=1.0))
    ax.add_patch(Polygon([(x + w, y), (x + w + d, y + d), (x + w + d, y + h + d), (x + w, y + h)], fc=fc, ec=ec, lw=1.0))
    ax.add_patch(Rectangle((x, y), w, h, fc="white", ec=ec, lw=1.0))
    cx = x + w / 2
    top = y + h - 0.06
    if stereo:
        ax.text(cx, top, stereo, ha="center", va="top", fontsize=bs - 0.4, color=MUTED, style="italic"); top -= LH(bs)
    ax.text(cx, top, title, ha="center", va="top", fontsize=ts, fontweight="bold"); top -= LH(ts)
    for ln in lines:
        ax.text(cx, top, ln, ha="center", va="top", fontsize=bs, color=LINE); top -= LH(bs)
    return dict(x=x, y=y, w=w, h=h, cx=cx, cy=y + h / 2)


def component(ax, x, y, w, h, title, lines=(), color="grey", ts=8, bs=6.7):
    box(ax, x, y, w, h, color=color, r=0.04)
    fc, ec = C[color]
    # UML component icon: a small box with two tabs, top-left corner
    ix, iy = x + 0.09, y + h - 0.2
    ax.add_patch(Rectangle((ix + 0.04, iy), 0.12, 0.14, fc="white", ec=ec, lw=0.8))
    ax.add_patch(Rectangle((ix, iy + 0.085), 0.08, 0.035, fc="white", ec=ec, lw=0.8))
    ax.add_patch(Rectangle((ix, iy + 0.025), 0.08, 0.035, fc="white", ec=ec, lw=0.8))
    cx = x + w / 2
    ax.text(cx, y + h - 0.09, title, ha="center", va="top", fontsize=ts, fontweight="bold")
    top = y + h - 0.09 - LH(ts)
    for i, ln in enumerate(lines):
        ax.text(cx, top - i * LH(bs), ln, ha="center", va="top", fontsize=bs, color=LINE)
    return dict(x=x, y=y, w=w, h=h, cx=cx, cy=y + h / 2, top=y + h, bottom=y, left=x, right=x + w)


# ── Figure 3.1: use case ───────────────────────────────────────────────────


def fig_usecase():
    H = 6.2
    fig, ax = canvas(H)
    bx, by, bw, bhh = 1.55, 0.35, 3.0, 5.55
    ax.add_patch(FancyBboxPatch((bx, by), bw, bhh, boxstyle="round,pad=0,rounding_size=0.12", fc="#ffffff", ec=INK, lw=1.4))
    ax.text(bx + bw / 2, by + bhh - 0.12, "NIDS", ha="center", va="top", fontsize=10, fontweight="bold")
    A = {  # left column
        "login": (2.35, 5.05, "Log in"),
        "classify": (2.35, 4.25, "Classify traffic\n(single / batch)"),
        "capture": (2.35, 3.45, "Start / stop\nlive capture"),
        "users": (2.35, 2.65, "Manage users"),
        "train": (2.35, 1.85, "Train models"),
    }
    B = {  # right column
        "verdicts": (3.75, 4.25, "View live verdicts\nand alerts"),
        "blocked": (3.75, 3.45, "View blocked IPs\nand statistics"),
        "password": (3.75, 2.65, "Change own\npassword"),
    }
    for x, y, t in list(A.values()) + list(B.values()):
        usecase(ax, x, y, t, w=1.25, h=0.5, fs=8)
    ext = (0.7, 4.3); adm = (0.7, 1.7); vwr = (5.35, 3.3)
    actor(ax, *ext, "External System"); actor(ax, *adm, "Administrator"); actor(ax, *vwr, "Viewer")
    ek = (ext[0] + 0.12, ext[1] + 0.3); ak = (adm[0] + 0.12, adm[1] + 0.3); vk = (vwr[0] - 0.12, vwr[1] + 0.3)
    for k in ("login", "classify"):
        x, y, _ = A[k]; ax.plot([ek[0], x - 0.62], [ek[1], y], color=INK, lw=1.0)
    for k in ("capture", "users", "train"):
        x, y, _ = A[k]; ax.plot([ak[0], x - 0.62], [ak[1], y], color=INK, lw=1.0)
    for k in B:
        x, y, _ = B[k]; ax.plot([vk[0], x + 0.62], [vk[1], y], color=INK, lw=1.0)
    ax.plot([vk[0], A["login"][0] + 0.62], [vk[1], A["login"][1]], color=INK, lw=1.0)
    path(ax, [(adm[0], adm[1] - 0.45), (adm[0], 0.12), (vwr[0], 0.12), (vwr[0], vwr[1] - 0.5)], color=INK, lw=1.0, hollow=True, ms=11)
    label(ax, 3.05, 0.12, "Administrator inherits all Viewer use cases", fs=7.5, bg="white")
    save(fig, "usecase.png")

# ── Figure 3.2: class diagram ─────────────────────────────────────────────
def gen_arrow(ax, child, parent_pt):
    """UML generalisation: hollow triangle at the parent."""
    arrow(ax, (child["cx"], child["top"]), parent_pt, hollow=True, ms=12, lw=0.9)



def fig_class():
    H = 8.5
    fig, ax = canvas(H)
    base = klass(ax, 2.05, 8.35, 1.9, "BaseModel", stereo="«abstract»",
                 attrs=["is_fitted : bool", "n_features_, n_classes_"],
                 methods=["+ fit(X, y)", "+ predict(X) / predict_proba(X)", "+ save(path) / load(path)"], color="indigo")
    y2 = 6.75
    dt = klass(ax, 0.12, y2, 1.38, "DecisionTree", ["max_depth, criterion", "root : Node"], ["+ fit() / predict()", "+ tree_depth()"], "purple")
    rf = klass(ax, 1.62, y2, 1.42, "RandomForest", ["n_estimators = 150", "trees[], oob_score_"], ["+ fit(X, y)  [n_jobs]", "+ feature_importances()"], "purple")
    mlp = klass(ax, 3.16, y2, 1.38, "MLPClassifier", ["layers 256-128-64", "dropout, l2, Adam"], ["+ fit(X, y, X_val)", "+ predict_proba(X)"], "purple")
    iso = klass(ax, 4.66, y2, 1.22, "IsolationForest", ["n_estimators = 150", "threshold_"], ["+ fit(X_benign)", "+ anomaly_score(X)"], "green")
    for k in (dt, rf, mlp, iso):
        gen_arrow(ax, k, (base["cx"], base["bottom"]))
    # composition RandomForest ◆── 1..* DecisionTree
    ax.plot([dt["right"], rf["left"]], [y2 - 0.55, y2 - 0.55], color=INK, lw=0.9)
    ax.add_patch(Polygon([(rf["left"], y2 - 0.55), (rf["left"] - 0.06, y2 - 0.505), (rf["left"] - 0.12, y2 - 0.55), (rf["left"] - 0.06, y2 - 0.595)], fc=INK, ec=INK))
    ax.text(dt["right"] + 0.06, y2 - 0.7, "1..*", fontsize=5.8, color=LINE, ha="center", va="top")

    y3 = 5.05
    fa = klass(ax, 0.12, y3, 1.55, "FlowAccumulator", ["5-tuple key, timestamps", "payload lens, flags, IATs"], ["+ add_packet(...)", "+ to_features() → 30", "+ closed (RST / 2×FIN)"], "teal")
    ens = klass(ax, 2.05, y3, 1.9, "EnsembleNIDS", ["rf, mlp, iso", "rf_weight = 0.9, mlp_weight = 0.1", "anomaly_boost = 0.9"], ["+ predict(X)", "+ predict_with_detail(X)"], "indigo")
    pre = klass(ax, 4.33, y3, 1.55, "Preprocessor", ["scaler_mean, scaler_std", "selected_features"], ["+ fit(X, y) / transform(X)", "+ stratified_split()"], "grey")
    for k in (rf, mlp, iso):
        arrow(ax, (k["cx"], k["bottom"]), (ens["cx"] + (k["cx"] - ens["cx"]) * 0.35, ens["top"]), lw=0.9, ms=8)
    label(ax, ens["cx"], ens["top"] + 0.13, "combines", fs=6.4)

    y4 = 3.35
    sn = klass(ax, 0.12, y4, 1.55, "PacketSniffer", ["interface, bpf_filter", "flows : dict[key, Flow]"], ["+ start() / stop()", "+ parse_packet(pkt)", "- _classify_active()"], "teal")
    eng = klass(ax, 2.05, y4, 1.9, "InferenceEngine", ["preprocessor, ensemble", "latency percentiles"], ["+ predict(flow | flows)", "+ stats()"], "blue")
    am = klass(ax, 4.33, y4, 1.55, "AlertManager", ["alerts : deque(1000)", "severity / action maps"], ["+ record(result, ip)", "+ recent() / summary()"], "orange")
    # aggregation: PacketSniffer ◇── 1..* FlowAccumulator (vertical, short)
    ax.plot([sn["cx"], sn["cx"]], [sn["top"] + 0.1, fa["bottom"]], color=INK, lw=0.9)
    ax.add_patch(Polygon([(sn["cx"], sn["top"]), (sn["cx"] - 0.045, sn["top"] + 0.06), (sn["cx"], sn["top"] + 0.12), (sn["cx"] + 0.045, sn["top"] + 0.06)], fc="white", ec=INK, lw=0.9))
    ax.text(sn["cx"] + 0.06, fa["bottom"] - 0.05, "1..*", fontsize=5.8, color=LINE, va="top")
    arrow(ax, (ens["cx"], ens["bottom"]), (eng["cx"], eng["top"]), lw=0.9, ms=8, text="uses", toff=(0.22, 0))
    arrow(ax, (pre["cx"] - 0.3, pre["bottom"]), (eng["right"] - 0.25, eng["top"]), lw=0.9, ms=8, text="uses", toff=(0.3, 0))
    ymid = eng["bottom"] + eng["h"] * 0.35
    arrow(ax, (sn["right"], ymid), (eng["left"], ymid), lw=0.9, ms=8)
    ax.text((sn["right"] + eng["left"]) / 2, ymid - 0.07, "flows", ha="center", va="top", fontsize=6.0, color=LINE)
    arrow(ax, (eng["right"], ymid), (am["left"], ymid), lw=0.9, ms=8)
    ax.text((eng["right"] + am["left"]) / 2, ymid - 0.07, "record()", ha="center", va="top", fontsize=6.0, color=LINE)

    y5 = 1.7
    al = klass(ax, 0.12, y5, 1.55, "Allowlist", ["networks : list[CIDR]"], ["+ is_allowed(ip)"], "red")
    rx = klass(ax, 2.05, y5, 1.9, "ResponseExecutor", ["policy : ResponsePolicy", "backend, allowlist", "min_confidence = 0.85"], ["+ enforce(alert)", "+ unblock(ip) / flush_all()"], "red")
    fb = klass(ax, 4.33, y5, 1.55, "FirewallBackend", stereo="«abstract»", methods=["+ setup()", "+ block_ip(ip, action, ttl)", "+ unblock(ip)"], color="red")
    arrow(ax, (am["cx"], am["bottom"]), (rx["right"] - 0.3, rx["top"]), lw=0.9, ms=8, text="on_alert →\nenforce()", toff=(0.42, 0.05))
    ymid2 = rx["bottom"] + rx["h"] / 2
    arrow(ax, (rx["left"], ymid2), (al["right"], ymid2), lw=0.9, ms=8)
    ax.text((rx["left"] + al["right"]) / 2, ymid2 - 0.07, "checks", ha="center", va="top", fontsize=6.0, color=LINE)
    arrow(ax, (rx["right"], ymid2), (fb["left"], ymid2), lw=0.9, ms=8)
    ax.text((rx["right"] + fb["left"]) / 2, ymid2 - 0.07, "delegates", ha="center", va="top", fontsize=6.0, color=LINE)
    yb = 0.55
    for i, (nm, sub) in enumerate((("Nftables", "Linux"), ("LogOnly", "dry-run"), ("NoOp", "tests"))):
        b = klass(ax, 4.05 + i * 0.63, yb, 0.58, nm, methods=[sub], color="red", ts=6.8, bs=5.8)
        gen_arrow(ax, b, (fb["left"] + 0.2 + i * 0.6, fb["bottom"]))
    save(fig, "class.png")

# ── Figure 3.3: object diagram ────────────────────────────────────────────
def obj(ax, x, y_top, w, title, slots, color):
    lh = LH(6.6)
    h = 0.24 + len(slots) * lh + 0.1
    y = y_top - h
    fc, ec = C[color]
    ax.add_patch(Rectangle((x, y), w, h, fc="white", ec=ec, lw=1.0))
    ax.add_patch(Rectangle((x, y_top - 0.24), w, 0.24, fc=fc, ec=ec, lw=1.0))
    ax.text(x + w / 2, y_top - 0.12, title, ha="center", va="center", fontsize=7.3, fontweight="bold")
    ax.plot([x + 0.12, x + w - 0.12], [y_top - 0.205, y_top - 0.205], color=INK, lw=0.6)  # underline = instance
    for i, s in enumerate(slots):
        ax.text(x + 0.07, y_top - 0.3 - i * lh, s, ha="left", va="top", fontsize=6.3, color=LINE)
    return dict(x=x, y=y, w=w, h=h, cx=x + w / 2, cy=y + h / 2, top=y_top, bottom=y, left=x, right=x + w)



def fig_object():
    H = 4.6
    fig, ax = canvas(H)
    flow = obj(ax, 0.15, 4.2, 1.8, "flow : FlowFeatures", ["total_fwd_packets = 8", "total_bwd_packets = 8", "fwd_packet_length_mean = 45.9", "bwd_packet_length_mean = 1449.4", "flow_bytes_per_sec = 46 914", "rst_flag_count = 3"], "grey")
    eng = obj(ax, 2.12, 4.2, 1.7, "engine : InferenceEngine", ["ready = true", "models_dir = models_artifacts/"], "blue")
    ens = obj(ax, 2.12, 2.55, 1.7, "ensemble : EnsembleNIDS", ["rf_weight = 0.9", "mlp_weight = 0.1", "anomaly_boost = 0.9"], "indigo")
    res = obj(ax, 3.98, 4.2, 1.88, "result : PredictionResult", ["prediction = \"DDoS\"", "confidence = 0.9997", "anomaly_score = 0.41", "anomaly_flagged = false"], "purple")
    alt = obj(ax, 3.98, 2.72, 1.88, "alert : AlertRecord", ["alert_id = \"ALT-00000912\"", "severity = \"critical\"", "action = \"drop_and_notify_upstream\""], "orange")
    blk = obj(ax, 3.98, 1.4, 1.88, "block : BlockRecord", ["ip_address = \"203.0.113.42\"", "action_type = \"drop\"", "remaining_seconds = 86 400"], "red")
    arrow(ax, (flow["right"], flow["top"] - 0.35), (eng["left"], eng["top"] - 0.35), text="input", toff=(0, 0.09))
    arrow(ax, (eng["cx"], eng["bottom"]), (ens["cx"], ens["top"]), text="uses", toff=(0.2, 0))
    arrow(ax, (eng["right"], eng["top"] - 0.35), (res["left"], res["top"] - 0.35), text="produces", toff=(0, 0.09))
    arrow(ax, (res["cx"], res["bottom"]), (alt["cx"], alt["top"]), text="recorded as", toff=(0.38, 0))
    arrow(ax, (alt["cx"], alt["bottom"]), (blk["cx"], blk["top"]), text="enforced as", toff=(0.38, 0))
    label(ax, 1.05, 0.8, "Snapshot while one real DDoS flow from the\ncorrected CIC-IDS2017 test set is processed.", fs=6.8, bg=None)
    save(fig, "object.png")

# ── Figure 3.4: state diagram ─────────────────────────────────────────────

def fig_state():
    H = 3.6
    fig, ax = canvas(H)
    box(ax, 1.05, 1.4, 1.7, 0.8, "OBSERVED", ["traffic allowed", "verdicts recorded"], color="blue")
    box(ax, 3.75, 2.45, 1.95, 0.78, "RATE-LIMITED", ["PortScan · WebAttack", "TTL 1 h"], color="orange")
    box(ax, 3.75, 0.3, 1.95, 0.92, "BLOCKED / DROPPED", ["BruteForce · Botnet", "Infiltration · DDoS  ·  TTL 24 h"], color="red", bs=6.4)
    terminal(ax, 0.35, 1.8); arrow(ax, (0.44, 1.8), (1.05, 1.8), text="first packet seen", toff=(0, 0.1), fs=6.4)
    arrow(ax, (2.75, 2.02), (3.75, 2.78), fs=6.3)
    label(ax, 2.85, 2.72, "attack and confidence ≥ threshold\nand not allowlisted and not already limited", fs=6.2)
    arrow(ax, (3.75, 2.52), (2.75, 1.9), ls="--")
    label(ax, 3.5, 2.06, "expires or unblocked", fs=6.2)
    arrow(ax, (2.75, 1.58), (3.75, 0.92), fs=6.3)
    label(ax, 2.85, 0.86, "attack and confidence ≥ threshold\nand not allowlisted and under block cap", fs=6.2)
    arrow(ax, (3.75, 1.12), (2.75, 1.7), ls="--")
    label(ax, 3.5, 1.56, "expires or unblocked", fs=6.2)
    terminal(ax, 5.75, 1.8, end=True)
    path(ax, [(4.72, 2.45), (4.72, 1.8), (5.62, 1.8)], ls="--")
    path(ax, [(4.72, 1.22), (4.72, 1.8)], ls="--", head=False)
    label(ax, 5.15, 1.97, "flush all blocks\n(operator)", fs=6.3)
    label(ax, 3.0, 0.1, "Thresholds come from the per-attack response policy (0.80–0.90) and the global gate min_confidence_to_enforce = 0.85.", fs=6.0, bg=None)
    save(fig, "state.png")

# ── Figure 3.5: sequence diagram ──────────────────────────────────────────

def fig_sequence():
    H = 6.5
    fig, ax = canvas(H)
    names = ["API client", "API routes\n(FastAPI)", "Inference\nEngine", "Preprocessor", "Ensemble\nNIDS", "Alert\nManager", "Response\nExecutor", "Dashboard\n(WebSocket)"]
    xs = [0.4 + i * 0.745 for i in range(8)]
    top, bottom = H - 0.15, 0.32
    for x, n in zip(xs, names):
        box(ax, x - 0.34, top - 0.42, 0.68, 0.42, color="indigo")
        ax.text(x, top - 0.21, n, ha="center", va="center", fontsize=6.6, fontweight="bold", linespacing=1.1)
        ax.plot([x, x], [top - 0.42, bottom], color="#444444", lw=0.9, ls=(0, (3, 3)), zorder=0.5)  # behind notes/boxes
    cl, rt, en, pr, es, am, rx, db = xs

    def msg(y, a, b, text, ret=False, fs=6.4):
        arrow(ax, (a, y), (b, y), ls="--" if ret else "-", lw=0.9, ms=8)
        label(ax, (a + b) / 2, y + 0.075, text, fs=fs, bg="white")

    def note(x, y, lines, w, fs=5.8):
        h = 0.06 + len(lines) * LH(fs) + 0.04
        box(ax, x, y - h / 2, w, h, color="grey", r=0.03)
        for i, ln in enumerate(lines):
            ax.text(x + w / 2, y + h / 2 - 0.05 - i * LH(fs), ln, ha="center", va="top", fontsize=fs, color=LINE)

    y = top - 0.75
    msg(y, cl, rt, "POST /predict + JWT"); y -= 0.42
    note(rt + 0.05, y, ["authenticate (JWT / API key)", "rate-limit 240 req/min", "validate the 30 features"], 1.25); y -= 0.44
    msg(y, rt, en, "predict(flow)"); y -= 0.34
    msg(y, en, pr, "transform(X)"); y -= 0.3
    msg(y, pr, en, "scaled X", ret=True); y -= 0.34
    msg(y, en, es, "predict_with_detail(X)"); y -= 0.3
    msg(y, es, en, "class · probabilities · anomaly score", ret=True); y -= 0.34
    msg(y, en, rt, "result (prediction, confidence, anomaly)", ret=True); y -= 0.52
    fy_top = y + 0.36                       # opt frame: only when the verdict is an attack
    msg(y, rt, am, "record(result, source_ip)"); y -= 0.34
    msg(y, am, rx, "enforce(alert)"); y -= 0.36
    note(rx - 0.45, y, ["confidence gate", "allowlist · dedup", "backend.block_ip()"], 0.9); y -= 0.4
    msg(y, rx, am, "block record / None", ret=True); y -= 0.3
    msg(y, am, rt, "alert_id", ret=True); y -= 0.5
    fy_bot = y + 0.24
    ax.add_patch(Rectangle((rt - 0.55, fy_bot), db - rt + 0.15, fy_top - fy_bot, fc="none", ec=C["orange"][1], lw=0.9))
    ax.add_patch(Rectangle((rt - 0.55, fy_top - 0.17), 0.72, 0.17, fc=C["orange"][0], ec=C["orange"][1], lw=0.9))
    ax.text(rt - 0.19, fy_top - 0.085, "opt  [is_attack]", ha="center", va="center", fontsize=6, fontweight="bold", color=C["orange"][1])
    msg(y, rt, db, "WebSocket push {type: flow, prediction, confidence, alert_id}", ret=True); y -= 0.38
    msg(y, rt, cl, "200 OK + JSON", ret=True)
    label(ax, 3.0, 0.12, "Solid = synchronous call · dashed = return or asynchronous push.  Flows from the live sniffer follow the same path from predict() onward.", fs=6.0, bg=None)
    save(fig, "sequence.png")

# ── Figure 3.6: activity diagram ──────────────────────────────────────────
def fig_activity():
    H = 9.2
    fig, ax = canvas(H)
    cx = 3.0
    def act(y, lines, color="blue", w=2.9, h=0.5):
        return box(ax, cx - w / 2, y - h / 2, w, h, lines=lines, color=color, bs=7.2)
    terminal(ax, cx, 8.95)
    act(8.55, ["Receive flow", "REST /predict · batch · live packet capture"]); arrow(ax, (cx, 8.86), (cx, 8.8))
    arrow(ax, (cx, 8.3), (cx, 8.15))
    act(7.9, ["Authenticate (JWT / API key), rate-limit,", "validate the 30-feature schema"]); arrow(ax, (cx, 7.65), (cx, 7.55))
    diamond(ax, cx, 7.2, 1.35, 0.6, "request\nvalid?")
    box(ax, 4.4, 7.0, 1.5, 0.4, lines=["Reject: HTTP 401 / 429 / 422"], color="red", bs=6.6)
    arrow(ax, (cx + 0.675, 7.2), (4.4, 7.2), text="no", toff=(0, 0.08)); terminal(ax, 5.15, 6.45, end=True); arrow(ax, (5.15, 7.0), (5.15, 6.58))
    arrow(ax, (cx, 6.9), (cx, 6.75), text="yes", toff=(0.18, 0))
    act(6.5, ["Build feature vector; clean ±∞/NaN;", "z-score with training-set statistics"]); arrow(ax, (cx, 6.25), (cx, 6.13))
    act(5.88, ["Random Forest + MLP soft vote", "P = 0.9·P_RF + 0.1·P_MLP"], color="indigo"); arrow(ax, (cx, 5.63), (cx, 5.51))
    act(5.26, ["Isolation Forest anomaly score", "(trained on benign flows only)"], color="green"); arrow(ax, (cx, 5.01), (cx, 4.87))
    diamond(ax, cx, 4.45, 2.7, 0.8, "benign vote and anomaly ≥ 0.9\nand max attack prob ≥ 0.15 ?")
    box(ax, 0.2, 4.2, 1.35, 0.5, lines=["Override → most likely", "attack class (zero-day guard)"], color="yellow", bs=6.6)
    arrow(ax, (cx - 1.35, 4.45), (1.55, 4.45), text="yes", toff=(0, 0.08))
    arrow(ax, (cx, 4.05), (cx, 3.9), text="no", toff=(0.18, 0))
    diamond(ax, cx, 3.6, 1.35, 0.6, "attack?")
    path(ax, [(0.875, 4.2), (0.875, 3.6), (cx - 0.675, 3.6)])
    box(ax, 4.45, 3.35, 1.4, 0.5, lines=["Record benign verdict", "(stats, WebSocket live feed)"], color="grey", bs=6.6)
    arrow(ax, (cx + 0.675, 3.6), (4.45, 3.6), text="no", toff=(0, 0.08))
    arrow(ax, (cx, 3.3), (cx, 3.15), text="yes", toff=(0.18, 0))
    act(2.9, ["Create alert: severity + recommended action;", "append alerts.jsonl; push to dashboard"], color="orange"); arrow(ax, (cx, 2.65), (cx, 2.48))
    diamond(ax, cx, 2.05, 3.3, 0.86, "enforcement on and confidence ≥ policy threshold\nand not allowlisted and not already blocked\nand below block cap ?")
    arrow(ax, (cx, 1.62), (cx, 1.47), text="yes", toff=(0.18, 0))
    act(1.22, ["Apply action via firewall backend", "rate-limit / block / drop with TTL (nftables · log-only)"], color="red", w=3.3)
    arrow(ax, (cx, 0.97), (cx, 0.82))
    act(0.6, ["Update metrics, latency stats and telemetry"], color="green", h=0.4)
    path(ax, [(cx + 1.65, 2.05), (5.5, 2.05), (5.5, 0.6), (cx + 1.45, 0.6)], text="no", tpt=(4.35, 2.14))
    path(ax, [(5.15, 3.35), (5.15, 2.85), (5.7, 2.85), (5.7, 0.72), (cx + 1.45, 0.72)])
    arrow(ax, (cx, 0.4), (cx, 0.3)); terminal(ax, cx, 0.2, end=True)
    save(fig, "activity.png")


# ── Figure 3.7: system architecture ───────────────────────────────────────


def fig_arch():
    layers = [
        ("Traffic input layer", ["Live packets from the\nnetwork interface", "Flow records from\nexternal sensors (REST)"]),
        ("API and security layer", ["REST routes\n(predict, alerts, blocks)", "JWT login and roles\n(admin, viewer)", "Rate limiting and\ninput validation", "WebSocket push\nto the dashboard"]),
        ("Detection layer", ["Preprocessor\n(clean, scale)", "Random Forest + MLP\nweighted vote", "Isolation Forest\nanomaly override", "Verdict: class,\nconfidence, anomaly"]),
        ("Response layer", ["Alert manager\n(severity, action)", "Enforcement\n(rate-limit, block, drop)", "Dashboard, metrics\nand logs"]),
        ("Data and training layer", ["Corrected CIC-IDS2017\ndataset", "Training pipeline\n(RF, MLP, IF, tuning)", "Model artifacts\nloaded at start-up"]),
    ]
    LH_, GAP, TOP = 1.02, 0.34, 0.15
    H = TOP + len(layers) * LH_ + (len(layers) - 1) * GAP + 0.1
    fig, ax = canvas(H)
    y = H - TOP
    arrows = ["packets / flow records", "30 flow features", "verdict per flow", "trained models (dashed: offline)"]
    for i, (title, items) in enumerate(layers):
        y0 = y - LH_
        ax.add_patch(FancyBboxPatch((0.15, y0), 5.7, LH_, boxstyle="round,pad=0,rounding_size=0.08", fc="white", ec=INK, lw=1.5))
        ax.text(0.3, y - 0.1, title, ha="left", va="top", fontsize=9.5, fontweight="bold")
        n = len(items); w = (5.4 - 0.15 * (n - 1)) / n
        for j, it in enumerate(items):
            bx = 0.3 + j * (w + 0.15)
            box(ax, bx, y0 + 0.1, w, 0.52, lines=it.split("\n"), color="white", bs=8, r=0.04, lw=1.1)
        if i < len(layers) - 1:
            nxt_top = y0 - GAP
            if i == len(layers) - 2:   # training layer feeds the detection layer offline
                path(ax, [(5.3, nxt_top), (5.3, y0)], ls="--", ms=9)
                label(ax, 4.05, (y0 + nxt_top) / 2, arrows[i], fs=8)
            else:
                arrow(ax, (3.0, y0), (3.0, nxt_top), ms=10)
                label(ax, 3.55, (y0 + nxt_top) / 2, arrows[i], fs=8, bg="white")
        y = y0 - GAP
    save(fig, "arch.png")

# ── Figure 3.8: component diagram ─────────────────────────────────────────

def fig_component():
    H = 6.1
    fig, ax = canvas(H)
    api = component(ax, 0.2, 5.25, 5.6, 0.68, "API layer  (src/api · src/auth · src/dashboard)", ["routes · Pydantic schemas · JWT + RBAC · rate limiter · dashboard HTML/JS · WebSocket hub"], color="blue")
    cap = component(ax, 0.2, 3.7, 1.2, 0.95, "Capture", ["src/capture", "PacketSniffer", "FlowAccumulator"], color="teal")
    inf = component(ax, 1.75, 3.7, 1.2, 0.95, "Inference", ["src/inference", "InferenceEngine", "AlertManager"], color="indigo")
    enf = component(ax, 3.3, 3.7, 1.15, 0.95, "Enforcement", ["src/enforcement", "executor · policy", "allowlist · backends"], color="red")
    mon = component(ax, 4.6, 3.7, 1.2, 0.95, "Monitoring", ["src/monitoring", "MetricsRegistry", "Prometheus text"], color="green")
    dat = component(ax, 0.2, 2.3, 1.2, 0.95, "Data", ["src/data", "dataset loader", "Preprocessor"], color="grey")
    mod = component(ax, 1.75, 2.3, 1.2, 0.95, "Models", ["src/models", "Tree · RF · MLP", "IF · Ensemble"], color="purple")
    utl = component(ax, 4.6, 2.3, 1.2, 0.95, "Utils", ["src/utils", "config · logging", "metrics (scratch)"], color="grey")
    trn = component(ax, 2.4, 0.35, 3.4, 0.85, "Training pipeline  (src/training · scripts/)", ["train_real_data · tune_ensemble · compare_models", "runs offline · writes models_artifacts/"], color="purple")
    def dep(pa, pb, text=None, tpt=None):
        path(ax, [pa, pb], ls="--", ms=8, text=text, tpt=tpt)
    dep((cap["cx"], api["bottom"]), (cap["cx"], cap["top"]), "start / stop", (cap["cx"] + 0.36, 5.0))
    dep((inf["cx"], api["bottom"]), (inf["cx"], inf["top"]), "predict()", (inf["cx"] + 0.32, 5.0))
    dep((enf["cx"], api["bottom"]), (enf["cx"], enf["top"]), "unblock / flush", (enf["cx"] + 0.4, 5.0))
    dep((mon["cx"], api["bottom"]), (mon["cx"], mon["top"]), "/metrics", (mon["cx"] + 0.3, 5.0))
    dep((cap["right"], 4.05), (inf["left"], 4.05)); ax.text((cap["right"] + inf["left"]) / 2, 4.12, "flows", ha="center", va="bottom", fontsize=6.2, color=LINE)
    dep((inf["right"], 4.05), (enf["left"], 4.05)); ax.text((inf["right"] + enf["left"]) / 2, 4.12, "alert", ha="center", va="bottom", fontsize=6.2, color=LINE)
    dep((inf["cx"], inf["bottom"]), (mod["cx"], mod["top"]))
    dep((inf["left"] + 0.15, inf["bottom"]), (dat["cx"] + 0.25, dat["top"]), "Preprocessor", (0.98, 3.47))
    dep((mod["left"], 2.77), (dat["right"], 2.77))
    dep((enf["right"], 3.95), (utl["left"] + 0.2, utl["top"]))
    dep((mon["cx"], mon["bottom"]), (utl["cx"], utl["top"]))
    path(ax, [(trn["left"], 0.62), (0.8, 0.62), (0.8, dat["bottom"])], ls="--", ms=8)
    dep((2.62, trn["top"]), (2.62, mod["bottom"]))
    label(ax, 3.15, 2.1, "Dependency rule: «use» arrows point inward only —\ndata, models and utils never import inference, API\nor training code, so every model can be trained,\ntested and reused on its own.", fs=6.5, bg=None, ha="left", va="top")
    label(ax, 1.6, 1.75, "- - ▶  «use» dependency", fs=6.5, bg=None)
    save(fig, "component.png")

# ── Figure 3.9: deployment diagram ────────────────────────────────────────


def fig_deployment():
    H = 3.9
    fig, ax = canvas(H)
    node3d(ax, 0.15, 2.1, 1.45, 1.0, "Monitored network", ["switch mirror port or", "host network interface"], stereo="«device»", ts=8.5, bs=7.5)
    node3d(ax, 2.05, 1.05, 2.0, 2.3, "NIDS server", ["Docker host"], stereo="«device»", ts=9, bs=7.5)
    box(ax, 2.2, 2.05, 1.7, 0.72, "NIDS API container", ["FastAPI + inference engine", "packet sniffer, port 8000"], color="white", ts=8, bs=7.2, r=0.04)
    box(ax, 2.2, 1.2, 1.7, 0.6, "Model artifacts and logs", ["ensemble.pkl, alerts.jsonl"], color="white", ts=8, bs=7.2, r=0.04)
    node3d(ax, 4.45, 2.1, 1.4, 1.0, "Analyst workstation", ["web browser:", "login and dashboard"], stereo="«device»", ts=8.5, bs=7.5)
    node3d(ax, 4.45, 0.35, 1.4, 0.8, "Trainer job", ["one-shot container,", "writes model artifacts"], stereo="«container»", ts=8.5, bs=7.5)
    arrow(ax, (1.68, 2.6), (2.05, 2.6), text="raw packets", toff=(0, 0.13), fs=7.5)
    arrow(ax, (4.45, 2.6), (4.13, 2.6), text="HTTP / WebSocket", toff=(0, 0.13), fs=7.5)
    arrow(ax, (2.98, 2.05), (2.98, 1.8), ms=8)
    path(ax, [(4.45, 0.75), (4.2, 0.75), (4.2, 1.5), (3.9, 1.5)], ls="--", ms=8)
    label(ax, 4.2, 1.15, "writes", fs=7.5)
    save(fig, "deployment.png")

# ── Figure 4.1: confusion matrix ──────────────────────────────────────────
def load_report():
    p = ROOT / "models_artifacts" / "reports" / "training_metrics.json"
    if p.exists():
        return json.loads(p.read_text())
    return None


def fig_confusion():
    rep = load_report()
    names = rep["class_names"] if rep else ["BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet", "Infiltration", "WebAttack"]
    cm = np.array(rep["models"]["ensemble"]["confusion_matrix"]) if rep else np.array(
        [[29991, 0, 7, 2, 0, 0, 0], [1, 9999, 0, 0, 0, 0, 0], [6, 0, 1494, 0, 0, 0, 0], [6, 0, 0, 1381, 0, 0, 0],
         [0, 0, 0, 0, 147, 0, 0], [1, 0, 0, 0, 0, 6, 0], [4, 0, 0, 0, 0, 0, 17]])
    fig = plt.figure(figsize=(W, 5.6))
    ax = fig.add_axes([0.2, 0.08, 0.76, 0.78])
    shade = np.log10(cm + 1)
    ax.imshow(shade, cmap="Greys", vmin=0, vmax=shade.max() * 1.25)
    n = len(names)
    for i in range(n):
        for j in range(n):
            v = cm[i, j]
            if v == 0:
                continue
            ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=8.5 if i == j else 7.5,
                    fontweight="bold" if i == j else "normal", color="white" if shade[i, j] > shade.max() * 0.55 else INK)
    ax.set_xticks(range(n)); ax.set_yticks(range(n))
    ax.set_xticklabels(names, fontsize=7.5, rotation=30, ha="right"); ax.set_yticklabels(names, fontsize=7.5)
    ax.set_xticks(np.arange(-0.5, n, 1), minor=True); ax.set_yticks(np.arange(-0.5, n, 1), minor=True)
    ax.grid(which="minor", color="white", lw=1.5); ax.tick_params(which="both", length=0)
    ax.set_xlabel("Predicted class", fontsize=8.5, fontweight="bold", labelpad=6)
    ax.set_ylabel("True class", fontsize=8.5, fontweight="bold", labelpad=6)
    total = int(cm.sum()); correct = int(np.trace(cm))
    fig.text(0.58, 0.955, f"Ensemble on the held-out test split: {total:,} real flows, {correct:,} correct ({correct / total:.2%})", ha="center", fontsize=8, fontweight="bold")
    fig.text(0.58, 0.915, "Cell shade is log-scaled so single misclassifications stay visible next to the 30,000 benign flows.", ha="center", fontsize=6.8, color=MUTED)
    save(fig, "confusion.png")


# ── Figure 4.2: old vs new per-class recall ───────────────────────────────
def fig_compare():
    names = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet", "Infiltration", "WebAttack"]
    old = [0.6423, 0.9142, 0.8007, 0.0, 0.9592, 1.0, 0.0]
    new = [0.9997, 0.9999, 0.9960, 0.9957, 1.0, 0.8571, 0.8095]
    fig = plt.figure(figsize=(W, 3.9))
    ax = fig.add_axes([0.09, 0.2, 0.89, 0.66])
    xs = np.arange(len(names)); wdt = 0.38
    b1 = ax.bar(xs - wdt / 2, old, wdt, color="#cbd5e1", edgecolor="#64748b", hatch="///", label="Previous model: 15 % subsample + synthetic padding")
    b2 = ax.bar(xs + wdt / 2, new, wdt, color="#3b82f6", edgecolor="#1d4ed8", label="Retrained model: corrected CIC-IDS2017, real flows only")
    for bars in (b1, b2):
        for b in bars:
            v = b.get_height()
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v * 100:.1f}%", ha="center", va="bottom", fontsize=6.1)
    ax.set_xticks(xs); ax.set_xticklabels(names, fontsize=7.5)
    ax.set_ylim(0, 1.12); ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0]); ax.set_yticklabels(["0", "25%", "50%", "75%", "100%"], fontsize=7)
    ax.set_ylabel("Recall on identical held-out flows", fontsize=7.8)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="y", color="#e5e7eb", lw=0.8); ax.set_axisbelow(True)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.2), ncol=1, fontsize=6.8, frameon=False)
    fig.text(0.53, 0.06, "Same 43,062 held-out flows for both models  ·  accuracy 69.1 % → 99.94 %  ·  false-positive rate 35.8 % → 0.03 %", ha="center", fontsize=6.5, color=MUTED)
    fig.text(0.53, 0.02, "Infiltration and WebAttack have only 7 and 21 test rows, so their bars are indicative only.", ha="center", fontsize=6.5, color=MUTED)
    save(fig, "compare.png")



# ── Figure 3.2: Gantt chart (planned schedule, eighth semester) ──────────────

def fig_gantt():
    tasks = [
        ("Topic study and project proposal", 1, 3),
        ("Requirement analysis and UML design", 3, 5),
        ("Data pipeline and preprocessing", 5, 6),
        ("Models from scratch: tree, RF, MLP, IF", 6, 8),
        ("Ensemble, training pipeline, evaluation", 8, 9),
        ("REST API, authentication, dashboard", 9, 11),
        ("Alerting, enforcement, monitoring", 11, 12),
        ("Live capture and feature alignment", 12, 13),
        ("Corrected dataset, retraining, results", 13, 14),
        ("Testing and documentation", 14, 15),
        ("Final report and defence preparation", 15, 16),
    ]
    milestones = [(3, "Proposal defence", -0.9), (12, "Mid-term defence", -1.7), (16, "Final defence", -0.9)]
    fig = plt.figure(figsize=(W, 5.0))
    ax = fig.add_axes([0.40, 0.11, 0.58, 0.78])
    for i, (name, a, b) in enumerate(tasks):
        ax.barh(i, b - a, left=a, height=0.62, color="white", edgecolor="black", lw=1.4, hatch="////" if i % 2 else None)
    ax.set_yticks(range(len(tasks))); ax.set_yticklabels([tk[0] for tk in tasks], fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlim(1, 16.6); ax.set_xticks(range(1, 17)); ax.set_xticklabels([str(w) for w in range(1, 17)], fontsize=8)
    ax.set_xlabel("Week of the eighth semester", fontsize=9)
    for wk, lab, row in milestones:
        ax.axvline(wk, color="black", lw=1.2, ls=(0, (4, 3)))
        ax.text(wk, row, lab, ha="right" if wk >= 15 else "center", va="bottom", fontsize=8, fontweight="bold", clip_on=False)
    ax.grid(axis="x", color="#bbbbbb", lw=0.7); ax.set_axisbelow(True)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(axis="y", length=0)
    save(fig, "gantt.png")

FIGS = {
    "usecase": fig_usecase, "class": fig_class, "state": fig_state, "sequence": fig_sequence,
    "activity": fig_activity, "arch": fig_arch, "deployment": fig_deployment,
    "confusion": fig_confusion, "gantt": fig_gantt,
}

if __name__ == "__main__":
    wanted = sys.argv[1:] or list(FIGS)
    for name in wanted:
        FIGS[name]()
