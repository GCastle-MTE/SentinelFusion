# ops_map.py
#
# Cinematic "ops console" world map: glowing arcs radiating from YOU out to
# each remote endpoint, with packets streaming along them and pulsing nodes
# (red = flagged). Built as an embeddable widget so app.py can drop it into
# the Metrics tab and feed it live data; also runs standalone with sample
# data so the look can be tuned:
#
#     python ops_map.py
#
# Pure Tkinter - no extra packages.
import math
import time
import tkinter as tk

# --- palette (gray console, neon accents) ---
BG = "#0a0f14"
GRID = "#14212a"
ARC_GLOW = "#0a5566"
ARC_MID = "#1f9fbf"
ARC_CORE = "#8fe9ff"
NODE = "#33c9e6"
NODE_HOT = "#ff4646"
YOU = "#dff4fb"
DOT_CORE = "#ffffff"
DOT_HALO = "#8fe9ff"
TEXT = "#c3d2d7"

# Distinct colors assigned per process (so each arc/node is identifiable).
APP_PALETTE = ["#33c9e6", "#ffa42b", "#ffcf5c", "#ff6b9d", "#7fe9ff",
               "#9d7bff", "#5ce6c0", "#ff6b6b", "#79b8ff", "#c0ff5a"]

MAX_NODES = 20  # keep the embedded view readable


def _dim(hexcol, factor):
    # Darken a #rrggbb color toward black by `factor` (0..1).
    try:
        h = hexcol.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f"#{int(r * factor):02x}{int(g * factor):02x}{int(b * factor):02x}"
    except Exception:
        return hexcol


def _fmt_b(n):
    n = float(n or 0)
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024 or u == "T":
            return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024


# Packet-dot colors by direction.
DOT_OUT = "#ffa42b"   # upload (you -> remote), MW objective amber
DOT_IN = "#4dd2ff"    # download (remote -> you), VISR cyan
LAND = "#14303c"      # continent fill - clearly lighter than the ocean
LAND_EDGE = "#3f8299"  # glowing cyan coastline for high contrast
LAND_GLOW = "#0f2731"  # soft halo drawn behind landmasses for depth
PANEL_BG = "#070d12"   # HUD panel backdrop
PANEL_EDGE = "#22323d"  # HUD panel border (cyan-tinted)
GRID_AXIS = "#2c4a5a"  # equator / prime-meridian reference lines (brighter)

# Stylized low-resolution continent outlines as (lon, lat) polygons. Not a
# precise coastline - just enough land to orient the eye. Can be swapped for a
# real GeoJSON later.
CONTINENTS = [
    [(-160, 66), (-140, 70), (-95, 72), (-60, 68), (-52, 47), (-80, 25),
     (-97, 16), (-105, 22), (-118, 30), (-125, 40), (-130, 55)],            # N America
    [(-80, 8), (-60, 12), (-35, -5), (-40, -23), (-55, -35), (-65, -45),
     (-72, -52), (-75, -45), (-70, -30), (-78, -15), (-82, -5)],            # S America
    [(-10, 43), (0, 51), (10, 58), (25, 70), (40, 68), (40, 50), (28, 40),
     (15, 38), (0, 40)],                                                     # Europe
    [(-16, 28), (-5, 36), (10, 37), (33, 32), (43, 12), (51, 11), (40, -5),
     (38, -20), (25, -34), (18, -35), (12, -18), (8, 5), (-8, 5), (-16, 15)],  # Africa
    [(40, 68), (60, 75), (100, 78), (140, 73), (170, 68), (180, 65),
     (160, 55), (140, 45), (135, 35), (122, 30), (120, 22), (105, 10),
     (95, 8), (80, 8), (72, 20), (60, 25), (50, 40), (40, 50)],             # Asia
    [(113, -22), (122, -18), (130, -12), (142, -11), (150, -22), (153, -28),
     (146, -38), (135, -35), (125, -33), (115, -30)],                       # Australia
    [(-45, 60), (-20, 60), (-18, 70), (-30, 82), (-55, 80), (-50, 70)],     # Greenland
]


class OpsMap:
    """Embeddable, data-driven traffic map.

        m = OpsMap(parent_frame, on_select=callback)
        m.set_self(lat, lon, "YOU (City)")
        m.set_endpoints([
            {"label": "youtube", "lat": 37.4, "lon": -122.0,
             "weight": 1.0, "flagged": False, "data": {...}},
            ...
        ])

    on_select(data) fires with an endpoint's `data` dict when its node is
    clicked. If no callback is given, a basic built-in popup is shown.
    """

    def __init__(self, parent, on_select=None):
        self.parent = parent
        self.on_select = on_select

        self.canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", self._on_resize)
        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<Motion>", self._on_motion)
        self.canvas.bind("<MouseWheel>", self._on_wheel)        # Windows / macOS
        self.canvas.bind("<Button-4>", self._on_wheel)          # Linux up
        self.canvas.bind("<Button-5>", self._on_wheel)          # Linux down

        self.W, self.H = 800, 480
        self.t0 = time.time()
        self.you_pos = (39.0, -98.0)   # lat, lon
        self.you_label = "YOU"
        self.endpoints = []

        self.zoom = 1.0
        self.pan_x = 0.0
        self.pan_y = 0.0
        self._press = None
        self._dragged = False
        self._zoom_hits = []     # [(x1,y1,x2,y2,action), ...]

        self.arcs = []
        self.node_items = {}
        self.dot_items = {}
        self.you_items = None
        self._app_colors = {}   # app name -> color (stable across refreshes)
        self._filter_app = None  # when set, only this process is drawn
        self._legend_hits = []   # [(x1,y1,x2,y2,app), ...] for click-to-isolate

        self._build_all()
        self._animate()

    # ---- public API ----
    def set_self(self, lat, lon, label="YOU"):
        if lat is None or lon is None:
            return
        self.you_pos = (float(lat), float(lon))
        self.you_label = label or "YOU"
        self._build_all()

    def set_endpoints(self, endpoints):
        eps = [e for e in (endpoints or [])
               if e.get("lat") is not None and e.get("lon") is not None]
        self.endpoints = eps[:MAX_NODES]
        self._build_all()

    # ---- projection / math ----
    def _project(self, lat, lon):
        # Equirectangular over the full canvas, then zoom + pan around centre.
        bx = (lon + 180.0) / 360.0 * self.W
        by = (90.0 - lat) / 180.0 * self.H
        sx = (bx - self.W / 2) * self.zoom + self.W / 2 + self.pan_x
        sy = (by - self.H / 2) * self.zoom + self.H / 2 + self.pan_y
        return (sx, sy)

    def _app_color(self, app):
        if not app:
            return "#9fb0a8"
        if app not in self._app_colors:
            self._app_colors[app] = APP_PALETTE[len(self._app_colors) % len(APP_PALETTE)]
        return self._app_colors[app]

    @staticmethod
    def _bezier(p0, c, p1, t):
        mt = 1 - t
        x = mt * mt * p0[0] + 2 * mt * t * c[0] + t * t * p1[0]
        y = mt * mt * p0[1] + 2 * mt * t * c[1] + t * t * p1[1]
        return x, y

    def _build_geometry(self):
        you = self._project(*self.you_pos)
        self.you_xy = you
        self.arcs = []
        for e in self.endpoints:
            p1 = self._project(e["lat"], e["lon"])
            mx, my = (you[0] + p1[0]) / 2, (you[1] + p1[1]) / 2
            dx, dy = p1[0] - you[0], p1[1] - you[1]
            dist = math.hypot(dx, dy)
            if dist:
                # Bow perpendicular to the line so arcs fan out and don't
                # collapse into a tangle at the origin.
                ox, oy = -dy / dist, dx / dist
                bow = min(dist * 0.22, 130)
                c = (mx + ox * bow, my + oy * bow)
            else:
                c = (mx, my - 40)
            weight = float(e.get("weight", 0.3))
            flagged = bool(e.get("flagged", False))
            app = str(e.get("app", "") or "")
            label = str(e.get("label", ""))
            color = NODE_HOT if flagged else self._app_color(app)
            out_b = float(e.get("out_bytes", 0) or 0)
            in_b = float(e.get("in_bytes", 0) or 0)

            ndots = 1 + int(weight * 5)
            tot = out_b + in_b
            n_out = round(ndots * out_b / tot) if tot > 0 else ndots
            n_out = max(0, min(ndots, n_out))
            n_in = ndots - n_out
            speed = 0.004 + weight * 0.010
            dots = []
            for i in range(n_out):
                dots.append({"t": i / max(n_out, 1), "speed": speed, "dir": 1})
            for i in range(n_in):
                dots.append({"t": i / max(n_in, 1), "speed": speed, "dir": -1})

            self.arcs.append({
                "p0": you, "c": c, "p1": p1, "weight": weight, "flagged": flagged,
                "app": app, "label": label, "color": color,
                "out_bytes": out_b, "in_bytes": in_b,
                "radius": 3 + weight * 6,
                "phase": (hash(label) % 100) / 100.0 * 6.283,
                "dots": dots, "data": e.get("data", {"label": label}),
            })

    # ---- build canvas items (rebuilt on data change / resize) ----
    def _build_all(self):
        c = self.canvas
        if not c.winfo_exists():
            return
        c.delete("all")
        self._build_geometry()
        flt = self._filter_app

        def visible(arc):
            return flt is None or arc["app"] == flt

        # continents backdrop (stylized, with a soft halo for depth)
        for poly in CONTINENTS:
            pts = []
            for lon, lat in poly:
                px, py = self._project(lat, lon)
                pts.extend([px, py])
            if len(pts) >= 6:
                c.create_polygon(*pts, fill="", outline=LAND_GLOW, width=6,
                                 smooth=True, tags="map")
                c.create_polygon(*pts, fill=LAND, outline=LAND_EDGE, width=1, tags="map")

        # graticule (projected so it zooms / pans; equator + meridian brighter)
        for lon in range(-150, 181, 30):
            x1, y1 = self._project(85, lon)
            x2, y2 = self._project(-85, lon)
            c.create_line(x1, y1, x2, y2, fill=(GRID_AXIS if lon == 0 else GRID), tags="map")
        for lat in range(-60, 91, 30):
            x1, y1 = self._project(lat, -179)
            x2, y2 = self._project(lat, 179)
            c.create_line(x1, y1, x2, y2, fill=(GRID_AXIS if lat == 0 else GRID), tags="map")

        # arcs, colored per process, width by volume
        for arc in self.arcs:
            if not visible(arc):
                continue
            pts = []
            for i in range(0, 21):
                x, y = self._bezier(arc["p0"], arc["c"], arc["p1"], i / 20)
                pts.extend([x, y])
            base = arc["color"]
            w = 1 + arc["weight"] * 3
            c.create_line(*pts, fill=_dim(base, 0.30), width=w + 4, smooth=True, capstyle="round", tags="map")
            c.create_line(*pts, fill=_dim(base, 0.65), width=w + 1, smooth=True, capstyle="round", tags="map")
            c.create_line(*pts, fill=base, width=max(1, w - 1), smooth=True, capstyle="round", tags="map")

        # header (panel backdrop + title)
        htxt = "SENTINELFUSION // GLOBAL TRAFFIC"
        hw = 7 * len(htxt) + 18
        c.create_rectangle(8, 8, 8 + hw, 30, fill=PANEL_BG, outline=PANEL_EDGE, tags="hud")
        c.create_text(16, 19, text=htxt, fill=ARC_CORE, anchor="w",
                      font=("Consolas", 11, "bold"), tags="hud")

        footer = ("scroll = zoom    drag = pan    node = process    "
                  "red = flagged    dots: amber up / cyan down")
        if flt:
            footer = f"[ filtered: {flt} - click its legend entry to reset ]    " + footer
        fw = 6 * len(footer) + 16
        fy = self.H - 26
        c.create_rectangle(8, fy, 8 + fw, fy + 16, fill=PANEL_BG, outline=PANEL_EDGE, tags="hud")
        c.create_text(14, fy + 8, anchor="w", fill=TEXT, font=("Consolas", 8),
                      text=footer, tags="hud")
        if not self.endpoints:
            c.create_text(self.W / 2, self.H / 2, fill=TEXT, font=("Consolas", 10),
                          text="waiting for external traffic...", tags="hud")

        # zoom controls panel (overlay, bottom-right): [ + ] [ - ] [ R ]
        bw, bh, gap = 26, 22, 4
        cluster_w = bw * 3 + gap * 2
        bx0 = self.W - cluster_w - 12
        by0 = self.H - bh - 30
        c.create_rectangle(bx0 - 6, by0 - 16, bx0 + cluster_w + 6, by0 + bh + 6,
                           fill=PANEL_BG, outline=PANEL_EDGE, tags="hud")
        c.create_text(bx0 + cluster_w / 2, by0 - 8, text=f"{self.zoom:.1f}x",
                      fill=TEXT, anchor="s", font=("Consolas", 8), tags="hud")
        self._zoom_hits = []
        for k, (sym, action) in enumerate((("+", "in"), ("\u2212", "out"), ("R", "reset"))):
            x1 = bx0 + k * (bw + gap)
            c.create_rectangle(x1, by0, x1 + bw, by0 + bh, fill="#161d22",
                               outline=TEXT, width=1, tags="hud")
            c.create_text(x1 + bw / 2, by0 + bh / 2, text=sym, fill=TEXT,
                          font=("Consolas", 12, "bold"), tags="hud")
            self._zoom_hits.append((x1, by0, x1 + bw, by0 + bh, action))

        # clickable process legend (top-right)
        self._legend_hits = []
        seen = []
        for arc in self.arcs:
            if arc["app"] and not arc["flagged"] and arc["app"] not in seen:
                seen.append(arc["app"])
        seen = seen[:8]
        has_flag = any(a["flagged"] for a in self.arcs)
        if seen or has_flag:
            lx = self.W - 172
            rows_total = len(seen) + (1 if has_flag else 0)
            c.create_rectangle(lx - 8, 6, self.W - 6, 30 + rows_total * 15,
                               fill=PANEL_BG, outline=PANEL_EDGE, tags="hud")
            c.create_text(lx, 12, text="PROCESSES (click to isolate)", fill=TEXT,
                          anchor="nw", font=("Consolas", 8, "bold"), tags="hud")
            row = 0
            for app in seen:
                yy = 30 + row * 15
                col = self._app_color(app)
                c.create_rectangle(lx, yy, lx + 9, yy + 9, fill=col, outline="", tags="hud")
                active = (flt is None or flt == app)
                c.create_text(lx + 14, yy + 4, text=app[:20],
                              fill=col if active else _dim(TEXT, 0.55), anchor="w",
                              font=("Consolas", 8, "bold" if flt == app else "normal"), tags="hud")
                self._legend_hits.append((lx - 2, yy - 2, lx + 152, yy + 11, app))
                row += 1
            if has_flag:
                yy = 30 + row * 15
                c.create_rectangle(lx, yy, lx + 9, yy + 9, fill=NODE_HOT, outline="", tags="hud")
                c.create_text(lx + 14, yy + 4, text="flagged (known-bad)", fill=NODE_HOT,
                              anchor="w", font=("Consolas", 8), tags="hud")

        # dynamic items (nodes + packet dots), moved each frame via coords()
        self.node_items, self.dot_items = {}, {}
        for i, arc in enumerate(self.arcs):
            if not visible(arc):
                continue
            x, y = arc["p1"]
            col = arc["color"]
            if arc["flagged"]:
                c.create_oval(x - 11, y - 11, x + 11, y + 11,
                              outline=NODE_HOT, width=2, tags="map")
                c.create_text(x - 13, y - 11, text="!", fill=NODE_HOT,
                              anchor="e", font=("Consolas", 11, "bold"), tags="map")
            glow = c.create_oval(x, y, x, y, outline=col, width=1, tags="map")
            core = c.create_oval(x, y, x, y, fill=col, outline="", tags="map")
            # 1px shadow behind the label keeps it readable over land and arcs.
            c.create_text(x + 11, y - 5, text=arc["label"], fill="#04080b",
                          anchor="w", font=("Consolas", 8), tags="map")
            c.create_text(x + 10, y - 6, text=arc["label"], fill=TEXT,
                          anchor="w", font=("Consolas", 8), tags="map")
            if arc["app"]:
                c.create_text(x + 11, y + 6, text=arc["app"][:18], fill="#04080b",
                              anchor="w", font=("Consolas", 7), tags="map")
                c.create_text(x + 10, y + 5, text=arc["app"][:18], fill=_dim(col, 0.95),
                              anchor="w", font=("Consolas", 7), tags="map")
            self.node_items[i] = (glow, core)
            ids = []
            for dot in arc["dots"]:
                dcol = DOT_OUT if dot["dir"] == 1 else DOT_IN
                halo = c.create_oval(0, 0, 0, 0, fill=_dim(dcol, 0.55), outline="", tags="map")
                cr = c.create_oval(0, 0, 0, 0, fill=dcol, outline="", tags="map")
                ids.append((halo, cr))
            self.dot_items[i] = ids

        yx, yy = self.you_xy
        yg = c.create_oval(yx, yy, yx, yy, outline=YOU, width=1, tags="map")
        yc = c.create_oval(yx, yy, yx, yy, fill=YOU, outline="", tags="map")
        c.create_text(yx + 1, yy + 1, text=self.you_label, fill="#04080b",
                      font=("Consolas", 9, "bold"), tags="map")
        yl = c.create_text(yx, yy, text=self.you_label, fill=YOU,
                           font=("Consolas", 9, "bold"), tags="map")
        self.you_items = (yg, yc, yl)

        # Keep the HUD panels (title, legend, zoom, footer) above the world.
        c.tag_raise("hud")

    # ---- per-frame animation ----
    def _animate(self):
        c = self.canvas
        if not c.winfo_exists():
            return
        try:
            t = time.time() - self.t0
            for i, (glow, core) in list(self.node_items.items()):
                arc = self.arcs[i]
                x, y = arc["p1"]
                base = arc["radius"]
                pulse = base + 1.5 * math.sin(t * 3 + arc["phase"])
                c.coords(glow, x - pulse - 3, y - pulse - 3, x + pulse + 3, y + pulse + 3)
                c.coords(core, x - pulse, y - pulse, x + pulse, y + pulse)
                for (halo, cr), dot in zip(self.dot_items[i], arc["dots"]):
                    dot["t"] += dot["speed"] * dot["dir"]
                    if dot["t"] > 1.0:
                        dot["t"] -= 1.0
                    elif dot["t"] < 0.0:
                        dot["t"] += 1.0
                    dx, dy = self._bezier(arc["p0"], arc["c"], arc["p1"], dot["t"])
                    c.coords(halo, dx - 3, dy - 3, dx + 3, dy + 3)
                    c.coords(cr, dx - 1.5, dy - 1.5, dx + 1.5, dy + 1.5)

            yx, yy = self.you_xy
            yp = 6 + 2 * math.sin(t * 2)
            yg, yc, yl = self.you_items
            c.coords(yg, yx - yp - 5, yy - yp - 5, yx + yp + 5, yy + yp + 5)
            c.coords(yc, yx - yp, yy - yp, yx + yp, yy + yp)
            c.coords(yl, yx, yy + yp + 12)
        except tk.TclError:
            return
        c.after(33, self._animate)

    # ---- interaction ----
    def _on_resize(self, evt):
        self.W, self.H = evt.width, evt.height
        self._build_all()

    def _on_press(self, evt):
        self._press = (evt.x, evt.y)
        self._dragged = False

    def _on_drag(self, evt):
        if self._press is None:
            return
        dx = evt.x - self._press[0]
        dy = evt.y - self._press[1]
        if abs(dx) > 3 or abs(dy) > 3:
            self._dragged = True
        if not self._dragged:
            return
        self._press = (evt.x, evt.y)
        self.pan_x += dx
        self.pan_y += dy
        # Move map items cheaply; shift in-memory geometry so animation tracks.
        self.canvas.move("map", dx, dy)
        for arc in self.arcs:
            arc["p0"] = (arc["p0"][0] + dx, arc["p0"][1] + dy)
            arc["c"] = (arc["c"][0] + dx, arc["c"][1] + dy)
            arc["p1"] = (arc["p1"][0] + dx, arc["p1"][1] + dy)
        self.you_xy = (self.you_xy[0] + dx, self.you_xy[1] + dy)
        self.canvas.delete("tip")

    def _on_release(self, evt):
        was_drag = self._dragged
        self._press = None
        self._dragged = False
        if was_drag:
            return
        # Zoom buttons first.
        for x1, y1, x2, y2, action in self._zoom_hits:
            if x1 <= evt.x <= x2 and y1 <= evt.y <= y2:
                if action == "reset":
                    self.zoom, self.pan_x, self.pan_y = 1.0, 0.0, 0.0
                    self._build_all()
                else:
                    self._zoom_at(self.W / 2, self.H / 2,
                                  1.3 if action == "in" else 1 / 1.3)
                return
        # Legend click -> isolate that process (toggle off if already active).
        for x1, y1, x2, y2, app in self._legend_hits:
            if x1 <= evt.x <= x2 and y1 <= evt.y <= y2:
                self._filter_app = None if self._filter_app == app else app
                self._build_all()
                return
        # Node click -> open detail (only nodes currently visible).
        for i in self.node_items:
            arc = self.arcs[i]
            nx, ny = arc["p1"]
            if (evt.x - nx) ** 2 + (evt.y - ny) ** 2 <= 12 ** 2:
                if self.on_select:
                    self.on_select(arc["data"])
                else:
                    self._popup(arc["data"])
                return

    def _on_wheel(self, evt):
        up = getattr(evt, "delta", 0) > 0 or getattr(evt, "num", 0) == 4
        self._zoom_at(evt.x, evt.y, 1.15 if up else 1 / 1.15)

    def _zoom_at(self, mx, my, factor):
        new = max(0.6, min(12.0, self.zoom * factor))
        if abs(new - self.zoom) < 1e-6:
            return
        # Keep the world point under (mx, my) fixed while scaling.
        bx = (mx - self.W / 2 - self.pan_x) / self.zoom + self.W / 2
        by = (my - self.H / 2 - self.pan_y) / self.zoom + self.H / 2
        self.zoom = new
        self.pan_x = mx - self.W / 2 - (bx - self.W / 2) * self.zoom
        self.pan_y = my - self.H / 2 - (by - self.H / 2) * self.zoom
        self._build_all()

    def _on_motion(self, evt):
        self.canvas.delete("tip")
        hit = None
        for i in self.node_items:
            arc = self.arcs[i]
            nx, ny = arc["p1"]
            if (evt.x - nx) ** 2 + (evt.y - ny) ** 2 <= 13 ** 2:
                hit = arc
                break
        if not hit:
            return
        info = (hit["data"] or {}).get("info") or {}
        lines = [hit["label"], f"proc: {hit['app'] or '?'}",
                 f"loc:  {info.get('country', '?')}",
                 f"pkts: {(hit['data'] or {}).get('count', '?')}",
                 f"up {_fmt_b(hit['out_bytes'])}  down {_fmt_b(hit['in_bytes'])}"]
        if hit["flagged"]:
            lines.append("** FLAGGED **")
            rsn = (hit["data"] or {}).get("reason")
            if rsn:
                # Wrap a long reason onto tidy tooltip-width lines.
                words, line = rsn.split(), ""
                for wd in words:
                    if len(line) + len(wd) + 1 > 40:
                        lines.append(line)
                        line = wd
                    else:
                        line = (line + " " + wd).strip()
                if line:
                    lines.append(line)
        w = 7 * max(len(s) for s in lines) + 14
        h = 13 * len(lines) + 8
        tx, ty = evt.x + 14, evt.y + 12
        if tx + w > self.W:
            tx = evt.x - w - 14
        if ty + h > self.H:
            ty = self.H - h - 4
        self.canvas.create_rectangle(tx, ty, tx + w, ty + h, fill="#0a0f12",
                                     outline=hit["color"], tags="tip")
        self.canvas.create_text(tx + 7, ty + 4, anchor="nw", fill=TEXT,
                                font=("Consolas", 8), text="\n".join(lines), tags="tip")

    def _popup(self, d):
        win = tk.Toplevel(self.parent)
        win.title(str(d.get("label", "endpoint")))
        win.configure(bg="#06140d")
        win.resizable(False, False)
        lines = [f"{k}: {v}" for k, v in d.items()] or ["(no detail)"]
        tk.Label(win, text="\n".join(lines), justify="left", bg="#06140d", fg=TEXT,
                 font=("Consolas", 10), padx=18, pady=14).pack()
        tk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 12))


# --- sample data for standalone preview ---
_SAMPLE_YOU = (39.0, -98.0)
_SAMPLE = [
    {"label": "youtube.com", "app": "chrome.exe", "lat": 37.42, "lon": -122.08, "weight": 1.00, "flagged": False,
     "out_bytes": 2_000_000, "in_bytes": 80_000_000,
     "data": {"label": "youtube.com", "ip": "142.250.80.46", "app": "chrome.exe", "country": "United States"}},
    {"label": "discord-gw", "app": "Discord.exe", "lat": 50.11, "lon": 8.68, "weight": 0.62, "flagged": False,
     "out_bytes": 9_000_000, "in_bytes": 11_000_000,
     "data": {"label": "discord-gw", "ip": "162.159.135.232", "app": "Discord.exe", "country": "Germany"}},
    {"label": "unknown-scan", "app": "?", "lat": 55.75, "lon": 37.62, "weight": 0.55, "flagged": True,
     "out_bytes": 40_000_000, "in_bytes": 1_000_000,
     "data": {"label": "unknown-scan", "ip": "185.0.0.1", "app": "?", "country": "Russia"}},
    {"label": "aws-ap", "app": "svchost.exe", "lat": 1.35, "lon": 103.82, "weight": 0.52, "flagged": False,
     "out_bytes": 6_000_000, "in_bytes": 6_000_000,
     "data": {"label": "aws-ap", "ip": "13.228.0.1", "app": "svchost.exe", "country": "Singapore"}},
    {"label": "akamai", "app": "chrome.exe", "lat": 51.51, "lon": -0.13, "weight": 0.40, "flagged": False,
     "out_bytes": 500_000, "in_bytes": 20_000_000,
     "data": {"label": "akamai", "ip": "23.62.0.1", "app": "chrome.exe", "country": "United Kingdom"}},
    {"label": "ntp-jp", "app": "svchost.exe", "lat": 35.68, "lon": 139.69, "weight": 0.34, "flagged": False,
     "out_bytes": 200_000, "in_bytes": 200_000,
     "data": {"label": "ntp-jp", "ip": "133.243.0.1", "app": "svchost.exe", "country": "Japan"}},
    {"label": "azure-au", "app": "System", "lat": -33.87, "lon": 151.21, "weight": 0.30, "flagged": False,
     "out_bytes": 3_000_000, "in_bytes": 1_500_000,
     "data": {"label": "azure-au", "ip": "20.213.0.1", "app": "System", "country": "Australia"}},
]


def main():
    root = tk.Tk()
    root.title("SentinelFusion // Global Traffic")
    root.configure(bg=BG)
    root.geometry("1120x640")
    m = OpsMap(root)
    m.set_self(_SAMPLE_YOU[0], _SAMPLE_YOU[1], "YOU")
    m.set_endpoints(_SAMPLE)
    root.mainloop()


if __name__ == "__main__":
    main()
