#!/usr/bin/env python3
"""
CTF Notifier — a system-tray app that notifies you about CTF competitions with
rewards (prizes / vouchers / cert bundles), plus page-watchers for events that
aren't on CTFtime (OffSec's The Gauntlet, OffSec giveaways).

Data sources (polled on an interval; "realtime" within the poll window):
  - CTFtime JSON API  https://ctftime.org/api/v1/events/   (official, exposes a
    per-event `prizes` field — this is the reward feed)
  - Web watchers       arbitrary pages, notify when the page text changes and
    contains trigger keywords (OffSec Gauntlet / giveaways)

It runs in the system tray with a live list of upcoming reward CTFs, a
"Check now" action, and quick links. If the tray backend is unavailable it
degrades to a headless notifier loop (notifications still fire).

Run:
    python3 ctf_notifier.py                 # tray (or headless fallback)
    python3 ctf_notifier.py --headless      # force no tray
    python3 ctf_notifier.py --once          # one poll then exit (for cron/testing)
    python3 ctf_notifier.py --test-notify    # fire a test desktop notification
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
CONFIG = {
    # How often to poll the sources, in minutes (floored at 10 to be kind to CTFtime).
    "poll_interval_min": 30,
    # How far ahead to look for upcoming events.
    "lookahead_days": 120,
    # Never fire more than this many individual "new CTF" notifications in one
    # poll; beyond it, a single summary notification is sent instead. Prevents a
    # notification storm when many events appear at once.
    "max_notifications_per_poll": 6,
    # Only surface CTFtime events that have a non-empty `prizes` field
    # (i.e. "with rewards"). Set False to also catch events whose title matches
    # a highlight keyword even with an empty prizes field.
    "require_prizes": True,
    # Events whose prizes/title mention any of these get a high-priority (critical)
    # notification and a star in the tray menu.
    "highlight_keywords": [
        "oscp", "offsec", "off-sec", "voucher", "certification", "certificate",
        "cert", "exam", "scholarship", "cash", "swag", "$", "€", "£", "usd",
        "btc", "prize pool", "hack the box", "htb", "burp",
    ],
    # Extra pages to watch (not on CTFtime). High-signal trigger words only: the
    # watcher alerts when one of these *newly appears* on the page, so rotating
    # tokens / build hashes in the page never cause false alarms.
    "web_watch": [
        {
            "name": "OffSec — The Gauntlet (free CTF, OSCP-course prizes)",
            "url": "https://www.offsec.com/events/the-gauntlet/",
            "keywords": ["season 4", "season 5", "register", "sign up", "signup",
                         "now open", "enroll", "apply now", "starts on"],
        },
        {
            "name": "OffSec — CTF / giveaways blog",
            "url": "https://www.offsec.com/blog/ctf/",
            "keywords": ["giveaway", "register now", "now open", "enter to win",
                         "sign up", "starts on"],
        },
    ],
    # Extra CTF feeds / sites shown as browsable bookmarks in the GUI (each gets
    # its own "Source" so you can filter by site). Add your own freely.
    "sites": [
        {"name": "CTFtime — all upcoming events", "source": "CTFtime",
         "url": "https://ctftime.org/event/list/upcoming", "note": "full global calendar"},
        {"name": "OffSec — The Gauntlet (free CTF, OSCP-course prizes)", "source": "OffSec",
         "url": "https://www.offsec.com/events/the-gauntlet/", "note": "free seasonal CTF, course prizes"},
        {"name": "OffSec — CTF / giveaways blog", "source": "OffSec",
         "url": "https://www.offsec.com/blog/ctf/", "note": "tournaments & giveaways"},
        {"name": "Hack The Box — CTF platform", "source": "HTB",
         "url": "https://ctf.hackthebox.com/", "note": "HTB-hosted CTFs"},
        {"name": "picoCTF", "source": "picoCTF",
         "url": "https://picoctf.org/", "note": "beginner-friendly, year-round"},
        {"name": "pwn.college", "source": "pwn.college",
         "url": "https://pwn.college/", "note": "free training dojos"},
        {"name": "r/securityCTF", "source": "Reddit",
         "url": "https://www.reddit.com/r/securityCTF/", "note": "announcements & writeups"},
    ],
    "ctftime_api": "https://ctftime.org/api/v1/events/",
    "user_agent": "ctf-notifier/1.0 (personal CTF reminder; runs locally)",
}

STATE_DIR = Path(os.path.expanduser("~/.local/share/ctf-notifier"))
STATE_FILE = STATE_DIR / "state.json"
LOG_FILE = STATE_DIR / "ctf-notifier.log"

GAUNTLET_URL = "https://www.offsec.com/events/the-gauntlet/"
CTFTIME_LIST_URL = "https://ctftime.org/event/list/"

# -----------------------------------------------------------------------------
# Shared runtime state
# -----------------------------------------------------------------------------
LATEST_EVENTS: list[dict] = []   # for the tray menu (sorted, soonest first)
STOP = threading.Event()         # set to shut the poll loop down
WAKE = threading.Event()         # set by "Check now" to poll immediately

log = logging.getLogger("ctf-notifier")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def setup_logging() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(sys.stderr),
            logging.FileHandler(LOG_FILE),
        ],
    )


def load_state() -> dict:
    try:
        with STATE_FILE.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"seen": {}, "hashes": {}}
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("state file unreadable (%s); starting fresh", exc)
        return {"seen": {}, "hashes": {}}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
        tmp.replace(STATE_FILE)
    except OSError as exc:
        log.error("could not save state: %s", exc)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def humanize_delta(target: datetime, ref: datetime) -> str:
    secs = (target - ref).total_seconds()
    past = secs < 0
    secs = abs(secs)
    if secs < 3600:
        out = f"{int(secs // 60)}m"
    elif secs < 86400:
        out = f"{int(secs // 3600)}h"
    else:
        out = f"{int(secs // 86400)}d"
    return f"{out} ago" if past else f"in {out}"


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_html(text: str) -> str:
    text = _TAG_RE.sub(" ", text or "")
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def has_keyword(text: str, keywords: list[str]) -> bool:
    low = (text or "").lower()
    return any(kw.lower() in low for kw in keywords)


def notify(title: str, body: str, highlight: bool = False, url: str | None = None) -> None:
    full_body = body + (f"\n{url}" if url else "")
    urgency = "critical" if highlight else "normal"
    try:
        subprocess.run(
            ["notify-send", "--app-name=CTF Notifier", f"--urgency={urgency}",
             "--icon=dialog-information", title, full_body],
            check=False,
        )
    except FileNotFoundError:
        log.warning("notify-send missing (install libnotify-bin). NOTIFY: %s | %s",
                    title, full_body)
    log.info("NOTIFY%s: %s | %s", " *" if highlight else "", title, body)
    print(f"[notify]{' *' if highlight else ''} {title} — {body}" + (f" ({url})" if url else ""))


def clear_notifications() -> None:
    """Dismiss currently-shown desktop notifications (best effort, any daemon)."""
    if shutil.which("dunstctl"):
        subprocess.run(["dunstctl", "close-all"], check=False)
        subprocess.run(["dunstctl", "history-clear"], check=False)
        log.info("cleared notifications via dunstctl")
        return
    if shutil.which("makoctl"):
        subprocess.run(["makoctl", "dismiss", "--all"], check=False)
        log.info("cleared notifications via makoctl")
        return
    if shutil.which("gdbus"):
        # No "close all" in the freedesktop spec, so close a range of ids. KDE /
        # GNOME accept this and dismiss any active popup with a matching id.
        for i in range(1, 401):
            subprocess.run(
                ["gdbus", "call", "--session", "--dest", "org.freedesktop.Notifications",
                 "--object-path", "/org/freedesktop/Notifications",
                 "--method", "org.freedesktop.Notifications.CloseNotification", str(i)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
        log.info("requested close of notification ids 1..400 via gdbus")
        return
    log.warning("no supported notification-clear tool found (dunstctl/makoctl/gdbus)")


# -----------------------------------------------------------------------------
# Sources
# -----------------------------------------------------------------------------
def fetch_ctftime_events(start_offset_days: int = 0) -> list[dict]:
    # start_offset_days lets the GUI reach back a couple of days to also catch
    # events that are currently running (start in the recent past, finish ahead).
    start = int(time.time()) - start_offset_days * 86400
    finish = int(time.time()) + CONFIG["lookahead_days"] * 86400
    try:
        resp = requests.get(
            CONFIG["ctftime_api"],
            params={"limit": 200, "start": start, "finish": finish},
            headers={"User-Agent": CONFIG["user_agent"]},
            timeout=25,
        )
    except requests.RequestException as exc:
        log.warning("CTFtime request failed: %s", exc)
        return []
    if resp.status_code != 200:
        log.warning("CTFtime API HTTP %s (a UA is required; may be rate-limited)",
                    resp.status_code)
        return []
    try:
        data = resp.json()
    except ValueError as exc:
        log.warning("CTFtime API returned non-JSON: %s", exc)
        return []
    return data if isinstance(data, list) else []


def process_ctftime(state: dict) -> list[dict]:
    """Fetch CTFtime, fire notifications, return the list for the tray menu."""
    events = fetch_ctftime_events()
    if not events:
        return LATEST_EVENTS  # keep whatever we last had on a transient failure

    ref = now_utc()
    seen = state.setdefault("seen", {})
    first_run = not state.get("initialized")
    live_count = 0
    new_notifs: list[dict] = []
    menu_events: list[dict] = []

    for ev in events:
        prizes = strip_html(ev.get("prizes") or "")
        title = (ev.get("title") or "Untitled CTF").strip()
        url = ev.get("url") or ev.get("ctftime_url") or CTFTIME_LIST_URL
        ev_id = str(ev.get("id") or ev.get("ctf_id") or url)

        keyword_hit = has_keyword(f"{title} {prizes}", CONFIG["highlight_keywords"])
        has_reward = bool(prizes) or keyword_hit
        if CONFIG["require_prizes"] and not has_reward:
            continue
        if not CONFIG["require_prizes"] and not keyword_hit and not prizes:
            continue

        start = parse_iso(ev.get("start"))
        finish = parse_iso(ev.get("finish"))
        if start is None:
            continue

        live = bool(start <= ref <= finish) if finish else (start <= ref)
        soon = timedelta(0) < (start - ref) <= timedelta(hours=24)
        highlight = keyword_hit

        when = ("LIVE NOW" if live else humanize_delta(start, ref))
        prize_tag = f" — {prizes[:60]}" if prizes else ""
        star = "* " if highlight else ""
        menu_events.append({
            "id": ev_id,
            "start": start.isoformat(),
            "sort": start.timestamp(),
            "url": url,
            "menu_label": f"{star}{title}  ({when}){prize_tag}",
        })

        if live:
            live_count += 1

        rec = seen.setdefault(ev_id, {})
        rec["title"] = title
        rec["finish"] = finish.isoformat() if finish else None

        if first_run:
            # Seed the baseline silently so we don't fire a notification storm
            # on the very first poll; a single summary is sent below instead.
            rec["new"] = True
            if live:
                rec["live"] = True
            if soon:
                rec["soon"] = True
            continue

        if not rec.get("new"):
            new_notifs.append({
                "title": title, "when": when, "start": start,
                "prizes": prizes, "highlight": highlight, "url": url,
            })
            rec["new"] = True
        if live and not rec.get("live"):
            notify(f"LIVE NOW: {title}",
                   f"Running until {finish.strftime('%Y-%m-%d %H:%M UTC') if finish else '?'}"
                   + (f"\nPrizes: {prizes[:160]}" if prizes else ""),
                   highlight=highlight, url=url)
            rec["live"] = True
        elif soon and not rec.get("soon"):
            notify(f"Starts {when}: {title}",
                   f"Begins {start.strftime('%Y-%m-%d %H:%M UTC')}"
                   + (f"\nPrizes: {prizes[:160]}" if prizes else ""),
                   highlight=highlight, url=url)
            rec["soon"] = True

    # prune entries whose event finished more than 14 days ago
    cutoff = ref - timedelta(days=14)
    for ev_id in list(seen.keys()):
        fin = parse_iso(seen[ev_id].get("finish"))
        if fin and fin < cutoff:
            del seen[ev_id]

    # Emit the collected "new event" notifications, capped to avoid a storm.
    cap = max(1, int(CONFIG.get("max_notifications_per_poll", 6)))
    if new_notifs:
        if len(new_notifs) <= cap:
            for n in new_notifs:
                notify(
                    f"New reward CTF: {n['title']}",
                    f"{n['when']} · {n['start'].strftime('%Y-%m-%d %H:%M UTC')}"
                    + (f"\nPrizes: {n['prizes'][:160]}" if n['prizes'] else ""),
                    highlight=n['highlight'], url=n['url'],
                )
        else:
            hot = sum(1 for n in new_notifs if n['highlight'])
            sample = ", ".join(n['title'] for n in new_notifs[:3])
            notify(
                f"{len(new_notifs)} new reward CTFs",
                f"Including: {sample}…"
                + (f"\n{hot} match OSCP/voucher/cert." if hot else "")
                + "\nOpen the tray menu or the browser to see them all.",
                highlight=hot > 0, url=CTFTIME_LIST_URL,
            )

    if first_run:
        state["initialized"] = True
        notify(
            "CTF Notifier started",
            f"Tracking {len(menu_events)} reward CTFs "
            f"({live_count} live now). You'll be alerted on new ones, "
            f"24h before they start, and when they go live.",
            url=CTFTIME_LIST_URL,
        )

    menu_events.sort(key=lambda e: e["sort"])
    return menu_events


def process_web_watch(state: dict) -> None:
    # Track the SET of trigger keywords present on each page. Alert only when a
    # new keyword appears (not on every byte change), so rotating tokens / build
    # hashes embedded in the page never trigger false alarms.
    seen_kw = state.setdefault("watch_keywords", {})
    for watch in CONFIG["web_watch"]:
        url = watch["url"]
        try:
            resp = requests.get(url, headers={"User-Agent": CONFIG["user_agent"]},
                                timeout=25)
        except requests.RequestException as exc:
            log.warning("web-watch fetch failed (%s): %s", url, exc)
            continue
        if resp.status_code != 200:
            log.warning("web-watch HTTP %s for %s", resp.status_code, url)
            continue

        low = strip_html(resp.text).lower()
        current = sorted({kw for kw in watch["keywords"] if kw.lower() in low})
        prev = seen_kw.get(url)
        seen_kw[url] = current

        if prev is None:
            log.info("web-watch baseline for %s: %s", watch["name"], current or "none")
            continue

        new_kw = [k for k in current if k not in prev]
        if new_kw:
            notify(f"Update: {watch['name']}",
                   "New on the page: " + ", ".join(new_kw) + " — check it now.",
                   highlight=True, url=url)
        else:
            log.debug("web-watch: %s unchanged trigger set", watch["name"])


# -----------------------------------------------------------------------------
# Poll loop
# -----------------------------------------------------------------------------
def do_poll(icon=None) -> None:
    global LATEST_EVENTS
    state = load_state()
    log.info("polling sources...")
    LATEST_EVENTS = process_ctftime(state)
    process_web_watch(state)
    save_state(state)
    log.info("poll complete: %d reward CTFs tracked", len(LATEST_EVENTS))
    if icon is not None:
        try:
            icon.menu = build_menu()
            icon.update_menu()
        except Exception as exc:  # tray refresh is best-effort
            log.debug("menu refresh failed: %s", exc)


def poll_loop(icon=None) -> None:
    interval = max(10, int(CONFIG["poll_interval_min"])) * 60
    while not STOP.is_set():
        try:
            do_poll(icon)
        except Exception as exc:
            log.exception("unhandled poll error: %s", exc)
        WAKE.wait(timeout=interval)
        WAKE.clear()


# -----------------------------------------------------------------------------
# Tray
# -----------------------------------------------------------------------------
def create_image():
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (64, 64), (13, 13, 13))
    d = ImageDraw.Draw(img)
    # little red flag on a yellow pole (matches the app theme)
    d.rectangle([18, 10, 21, 54], fill=(255, 210, 63))
    d.polygon([(21, 12), (50, 20), (21, 34)], fill=(255, 77, 77))
    return img


def build_menu():
    import pystray
    items = [
        pystray.MenuItem("CTF Notifier", None, enabled=False),
        pystray.Menu.SEPARATOR,
    ]
    if LATEST_EVENTS:
        items.append(pystray.MenuItem("Upcoming reward CTFs", None, enabled=False))
        for ev in LATEST_EVENTS[:12]:
            url = ev["url"]
            items.append(pystray.MenuItem(
                ev["menu_label"],
                (lambda _icon, _item, u=url: webbrowser.open(u)),
            ))
    else:
        items.append(pystray.MenuItem("(no reward CTFs found yet)", None, enabled=False))
    items += [
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Browse all CTFs (window)", lambda _i, _it: open_gui_process()),
        pystray.MenuItem("Clear all notifications", lambda _i, _it: clear_notifications()),
        pystray.MenuItem("Check now", lambda _i, _it: WAKE.set()),
        pystray.MenuItem("Open CTFtime list",
                         lambda _i, _it: webbrowser.open(CTFTIME_LIST_URL)),
        pystray.MenuItem("Open The Gauntlet",
                         lambda _i, _it: webbrowser.open(GAUNTLET_URL)),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", lambda icon, _it: (STOP.set(), WAKE.set(), icon.stop())),
    ]
    return pystray.Menu(*items)


def run_tray() -> bool:
    """Return True if the tray ran, False if it could not start (caller falls back)."""
    try:
        import pystray
    except Exception as exc:
        log.warning("pystray unavailable (%s) — falling back to headless", exc)
        return False
    try:
        icon = pystray.Icon("ctf-notifier", create_image(), "CTF Notifier")
        icon.menu = build_menu()

        def setup(icon):
            icon.visible = True
            threading.Thread(target=poll_loop, args=(icon,), daemon=True).start()

        icon.run(setup=setup)
        return True
    except Exception as exc:
        log.warning("tray failed to start (%s) — falling back to headless", exc)
        return False


# -----------------------------------------------------------------------------
# GUI — global CTF / event browser
# -----------------------------------------------------------------------------
def _archive_path() -> Path:
    return STATE_DIR / "archive.json"


def load_archive() -> dict:
    try:
        with _archive_path().open(encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("archive cache unreadable (%s); starting fresh", exc)
        return {}


def save_archive(data: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _archive_path().with_suffix(".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        tmp.replace(_archive_path())
    except OSError as exc:
        log.error("could not save archive cache: %s", exc)


def build_browser_data(start_offset_days: int = 3):
    """Return (active_rows, archive_rows).

    Active = live or upcoming events plus the configured sites/feeds. Finished
    events are written to a cache (~/.local/share/ctf-notifier/archive.json) and
    kept for 24h, then pruned — those populate the Archive tab. Events with
    TBD/TBA prizes are kept."""
    events = fetch_ctftime_events(start_offset_days=start_offset_days)
    ref = now_utc()
    active, finished_now = [], []
    for ev in events:
        start = parse_iso(ev.get("start"))
        finish = parse_iso(ev.get("finish"))
        if start is None:
            continue
        prizes = strip_html(ev.get("prizes") or "")
        keyword = has_keyword(f"{ev.get('title', '')} {prizes}", CONFIG["highlight_keywords"])
        row = {
            "source": "CTFtime",
            "title": (ev.get("title") or "Untitled").strip(),
            "url": ev.get("url") or ev.get("ctftime_url") or CTFTIME_LIST_URL,
            "start": start.strftime("%Y-%m-%d %H:%M"),
            "prizes": prizes or "TBD",
            "format": ev.get("format") or "",
            "weight": float(ev.get("weight") or 0),
            "restrictions": ev.get("restrictions") or "",
            "reward": bool(prizes) or keyword,
            "highlight": keyword,
            "finish_iso": finish.isoformat() if finish else None,
        }
        if finish is not None and finish < ref:
            row.update(status="FINISHED", live=False,
                       when=humanize_delta(finish, ref), sort=finish.timestamp())
            finished_now.append(row)
        else:
            live = (start <= ref <= finish) if finish else (start <= ref)
            row.update(status="LIVE" if live else "UPCOMING", live=live,
                       when="now" if live else humanize_delta(start, ref),
                       sort=start.timestamp())
            active.append(row)
    active.sort(key=lambda r: r["sort"])

    for s in CONFIG.get("sites", []):
        active.append({
            "source": s.get("source", "Site"), "title": s["name"], "url": s["url"],
            "status": "SITE", "when": "—", "start": "",
            "prizes": s.get("note", "open in browser"), "format": "site",
            "weight": 0.0, "restrictions": "", "live": False, "reward": False,
            "highlight": False, "finish_iso": None, "sort": float("inf"),
        })

    # merge freshly-finished into the cache; prune anything finished >24h ago
    archive = load_archive()
    for row in finished_now:
        archive[row["url"]] = row
    cutoff = ref - timedelta(hours=24)
    for url in list(archive):
        fin = parse_iso(archive[url].get("finish_iso"))
        if fin is None or fin < cutoff:
            del archive[url]
    save_archive(archive)

    archive_rows = []
    for row in archive.values():
        fin = parse_iso(row.get("finish_iso"))
        row = dict(row)
        row["status"] = "FINISHED"
        row["when"] = humanize_delta(fin, ref) if fin else "—"
        archive_rows.append(row)
    archive_rows.sort(key=lambda r: parse_iso(r.get("finish_iso")) or ref, reverse=True)
    return active, archive_rows


def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception as exc:
        msg = f"GUI needs Tkinter — install it with: sudo apt-get install -y python3-tk  ({exc})"
        log.error(msg)
        print(msg, file=sys.stderr)
        return 1
    try:
        root = tk.Tk()
    except Exception as exc:
        msg = f"Cannot open a window (no graphical display?): {exc}"
        log.error(msg)
        print(msg, file=sys.stderr)
        return 1

    root.title("CTF Notifier — Global CTF / Event Browser")
    root.geometry("1180x640")
    icon_path = Path(__file__).with_name("icon.png")
    if icon_path.exists():
        try:
            root._app_icon = tk.PhotoImage(file=str(icon_path))  # keep a ref
            root.iconphoto(True, root._app_icon)
        except Exception as exc:
            log.debug("could not set window icon: %s", exc)

    # --- black theme with red / yellow / colour accents ---
    BG, PANEL, STRIPE = "#0d0d0d", "#161616", "#141414"
    FG, MUTED, BORDER = "#e8e8e8", "#8a8a8a", "#2a2a2a"
    RED, YELLOW, GREEN, GOLD, CYAN = "#ff4d4d", "#ffd23f", "#46d369", "#ffb02e", "#4cc9f0"
    root.configure(bg=BG)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    base_font = ("DejaVu Sans", 10)
    bold_font = ("DejaVu Sans", 10, "bold")
    style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                    bordercolor=BORDER, font=base_font)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("TButton", background=PANEL, foreground=FG, bordercolor=BORDER,
                    focuscolor=BG, relief="flat", padding=6)
    style.map("TButton", background=[("active", "#3a1414"), ("pressed", "#4a1818")],
              foreground=[("active", RED)])
    style.configure("TCheckbutton", background=BG, foreground=FG, focuscolor=BG)
    style.map("TCheckbutton", background=[("active", BG)], foreground=[("active", YELLOW)])
    style.configure("TEntry", fieldbackground=PANEL, foreground=FG, insertcolor=RED,
                    bordercolor=BORDER, padding=4)
    style.configure("TCombobox", fieldbackground=PANEL, foreground=FG, background=PANEL,
                    arrowcolor=YELLOW, bordercolor=BORDER, padding=4)
    style.map("TCombobox", fieldbackground=[("readonly", PANEL)], foreground=[("readonly", FG)])
    root.option_add("*TCombobox*Listbox.background", PANEL)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.selectBackground", RED)
    root.option_add("*TCombobox*Listbox.selectForeground", "#000000")
    style.configure("Treeview", background=BG, fieldbackground=BG, foreground=FG,
                    bordercolor=BORDER, borderwidth=0, rowheight=26, font=base_font)
    style.configure("Treeview.Heading", background="#1c1c1c", foreground=YELLOW,
                    relief="flat", padding=6, font=bold_font)
    style.map("Treeview.Heading", background=[("active", "#262626")])
    style.map("Treeview", background=[("selected", "#333333")], foreground=[("selected", "#ffffff")])
    style.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BG,
                    bordercolor=BG, arrowcolor=FG)
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(16, 7))
    style.map("TNotebook.Tab", background=[("selected", "#1c1c1c")], foreground=[("selected", RED)])

    TAGS = {
        "even": {"background": BG}, "odd": {"background": STRIPE},
        "live": {"foreground": RED}, "up": {"foreground": YELLOW},
        "reward": {"foreground": GREEN}, "star": {"foreground": GOLD, "font": bold_font},
        "site": {"foreground": CYAN}, "finished": {"foreground": MUTED},
    }
    cols = ("source", "status", "title", "when", "start", "prizes", "format", "weight", "restrictions")
    heads = {"source": "Source", "status": "Status", "title": "Event", "when": "When",
             "start": "Start (UTC)", "prizes": "Prizes", "format": "Format",
             "weight": "Weight", "restrictions": "Restrictions"}
    widths = {"source": 90, "status": 84, "title": 280, "when": 74, "start": 130,
              "prizes": 280, "format": 80, "weight": 60, "restrictions": 120}

    store = {"active": [], "archive": [], "sort_col": "sort", "sort_desc": False,
             "urls": {"active": {}, "archive": {}}}

    # --- top control bar ---
    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    ttk.Label(top, text="Search").pack(side="left")
    search_var = tk.StringVar()
    ttk.Entry(top, textvariable=search_var, width=26).pack(side="left", padx=(6, 14))
    ttk.Label(top, text="Source").pack(side="left")
    source_var = tk.StringVar(value="All sources")
    source_combo = ttk.Combobox(top, textvariable=source_var, state="readonly",
                                width=14, values=["All sources"])
    source_combo.pack(side="left", padx=(6, 14))
    rewards_var = tk.BooleanVar(value=False)
    live_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(top, text="Rewards only", variable=rewards_var,
                    command=lambda: apply_filter()).pack(side="left", padx=6)
    ttk.Checkbutton(top, text="Live now", variable=live_var,
                    command=lambda: apply_filter()).pack(side="left", padx=6)
    status_lbl = ttk.Label(top, text="Loading…", style="Muted.TLabel")
    status_lbl.pack(side="right")
    ttk.Button(top, text="Refresh", command=lambda: load_async()).pack(side="right", padx=6)
    source_combo.bind("<<ComboboxSelected>>", lambda _e: apply_filter())

    # --- tabs: Active + Archive ---
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=(0, 4))
    frames, trees = {}, {}

    def make_tab(key, title):
        frame = ttk.Frame(notebook)
        tree = ttk.Treeview(frame, columns=cols, show="headings", style="Treeview")
        for c in cols:
            tree.heading(c, text=heads[c], command=lambda col=c, k=key: sort_tab(k, col))
            tree.column(c, width=widths[c], anchor="w")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview, style="Vertical.TScrollbar")
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        for tag, opts in TAGS.items():
            tree.tag_configure(tag, **opts)
        tree.bind("<Double-1>", lambda _e, k=key: open_selected(k))
        tree.bind("<Return>", lambda _e, k=key: open_selected(k))
        notebook.add(frame, text=title)
        frames[key] = frame
        trees[key] = tree

    make_tab("active", "Active")
    make_tab("archive", "Archive (24h)")

    hint = ttk.Label(root, padding=8, style="Muted.TLabel",
                     text="Double-click to open  ·  red = live  ·  yellow = upcoming  ·  "
                          "green = has prizes  ·  gold = OSCP/voucher/cert  ·  cyan = site/feed  ·  "
                          "Archive keeps finished events for 24h")
    hint.pack(fill="x")

    def sort_key(col):
        if col == "weight":
            return lambda r: r.get("weight", 0)
        if col in ("start", "when", "status"):
            return lambda r: r.get("sort", 0)
        return lambda r: str(r.get(col, "")).lower()

    def sort_tab(key, col):
        store["sort_desc"] = not store["sort_desc"] if store["sort_col"] == col else False
        store["sort_col"] = col
        store[key].sort(key=sort_key(col), reverse=store["sort_desc"])
        populate(key)

    def filter_rows(rows):
        q = search_var.get().strip().lower()
        src = source_var.get()
        out = []
        for r in rows:
            if rewards_var.get() and not r.get("reward"):
                continue
            if live_var.get() and not r.get("live"):
                continue
            if src != "All sources" and r.get("source") != src:
                continue
            if q and q not in r.get("title", "").lower() and q not in r.get("prizes", "").lower():
                continue
            out.append(r)
        return out

    def row_tags(r, idx, archive):
        stripe = "odd" if idx % 2 else "even"
        if archive:
            color = "star" if r.get("highlight") else "finished"
        elif r.get("highlight"):
            color = "star"
        elif r.get("live"):
            color = "live"
        elif r.get("status") == "SITE":
            color = "site"
        elif r.get("reward"):
            color = "reward"
        else:
            color = "up"
        return (stripe, color)

    def populate(key):
        tree = trees[key]
        tree.delete(*tree.get_children())
        umap = store["urls"][key]
        umap.clear()
        rows = filter_rows(store[key])
        archive = key == "archive"
        for i, r in enumerate(rows):
            iid = str(i)
            label = ("★ " + r["title"]) if r.get("highlight") else r["title"]
            tree.insert("", "end", iid=iid, tags=row_tags(r, i, archive), values=(
                r.get("source", ""), r.get("status", ""), label, r.get("when", ""),
                r.get("start", ""), r.get("prizes", "")[:90], r.get("format", ""),
                f'{r.get("weight", 0):.1f}', r.get("restrictions", ""),
            ))
            umap[iid] = r["url"]
        notebook.tab(frames[key], text=(
            f"Active ({len(rows)})" if key == "active" else f"Archive 24h ({len(rows)})"))
        if key == "active":
            live_n = sum(1 for r in rows if r.get("live"))
            reward_n = sum(1 for r in rows if r.get("reward"))
            status_lbl.config(text=f"{len(rows)} shown · {live_n} live · {reward_n} with rewards")

    def apply_filter():
        populate("active")
        populate("archive")

    def open_selected(key):
        url = store["urls"][key].get(trees[key].focus())
        if url:
            webbrowser.open(url)

    search_var.trace_add("write", lambda *_: apply_filter())

    def load_async():
        status_lbl.config(text="Loading…")

        def worker():
            try:
                data = build_browser_data()
            except Exception as exc:
                log.exception("GUI load failed: %s", exc)
                data = None
            root.after(0, lambda: on_loaded(data))

        threading.Thread(target=worker, daemon=True).start()

    def on_loaded(data):
        if data is None:
            status_lbl.config(text="Load failed — check connection / see log")
            return
        active, archive = data
        store["active"], store["archive"] = active, archive
        for key in ("active", "archive"):
            store[key].sort(key=sort_key(store["sort_col"]), reverse=store["sort_desc"])
        sources = sorted({r.get("source", "") for r in active + archive if r.get("source")})
        source_combo["values"] = ["All sources"] + sources
        apply_filter()

    load_async()
    root.mainloop()
    return 0


def open_gui_process() -> None:
    try:
        subprocess.Popen([sys.executable, os.path.abspath(__file__), "--gui"])
    except Exception as exc:
        log.error("could not launch GUI window: %s", exc)


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="CTF reward notifier (tray app)")
    ap.add_argument("--gui", action="store_true", help="open the global CTF browser window")
    ap.add_argument("--headless", action="store_true", help="run without a tray icon")
    ap.add_argument("--once", action="store_true", help="poll once and exit")
    ap.add_argument("--test-notify", action="store_true", help="send a test notification and exit")
    ap.add_argument("--clear-notifications", action="store_true",
                    help="dismiss all current desktop notifications and exit")
    args = ap.parse_args()

    setup_logging()
    log.info("CTF Notifier starting (state: %s)", STATE_DIR)

    if args.test_notify:
        notify("CTF Notifier test", "If you can see this, notifications work.",
               highlight=False, url=CTFTIME_LIST_URL)
        return 0

    if args.clear_notifications:
        clear_notifications()
        return 0

    if args.gui:
        return run_gui()

    if args.once:
        do_poll(None)
        return 0

    if args.headless or not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        if not args.headless:
            log.info("no DISPLAY/WAYLAND — running headless")
        poll_loop(None)
        return 0

    if not run_tray():
        poll_loop(None)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        STOP.set()
        sys.exit(0)
