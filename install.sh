#!/usr/bin/env bash
# Installer for CTF Notifier: sets up a venv, installs deps, and registers a
# boot/login autostart entry (XDG autostart .desktop) so it launches in the
# system tray each time you log in.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/.venv/bin/python"
PIP="$DIR/.venv/bin/pip"

echo "==> CTF Notifier install (dir: $DIR)"

# ---- system deps (best effort; needs sudo) ---------------------------------
# notify-send  -> libnotify-bin
# tray backend -> ayatana appindicator + PyGObject (so pystray can show a tray
#                 icon under XFCE/GNOME/KDE). Without these it still runs
#                 headless and notifications work; you just get no tray icon.
if command -v apt-get >/dev/null 2>&1; then
  echo "==> Installing system packages (libnotify-bin, appindicator, PyGObject)..."
  if sudo -n true 2>/dev/null || [ "$(id -u)" = "0" ]; then
    sudo apt-get update -qq || true
    sudo apt-get install -y libnotify-bin python3-tk python3-gi gir1.2-ayatanaappindicator3-0.1 \
      || sudo apt-get install -y libnotify-bin python3-tk python3-gi gir1.2-appindicator3-0.1 \
      || echo "    (some tray packages not found — headless/notification mode will still work)"
  else
    echo "    Skipping (no passwordless sudo). To enable the tray icon + GUI, run:"
    echo "      sudo apt-get install -y libnotify-bin python3-tk python3-gi gir1.2-ayatanaappindicator3-0.1"
  fi
fi

# ---- python venv -----------------------------------------------------------
echo "==> Creating virtualenv with system site-packages (so PyGObject is visible)..."
python3 -m venv --system-site-packages "$DIR/.venv"
"$PIP" install -q --upgrade pip
"$PIP" install -q -r "$DIR/requirements.txt"

# ---- app icon --------------------------------------------------------------
echo "==> Generating app icon..."
"$PY" "$DIR/make_icon.py" || echo "    (icon generation skipped — Pillow missing)"
ICON="$DIR/icon.png"
[ -f "$ICON" ] || ICON="dialog-information"

# ---- application launcher (Applications menu) ------------------------------
APPS="$HOME/.local/share/applications"
mkdir -p "$APPS"
LAUNCHER="$APPS/ctf-notifier.desktop"
cat > "$LAUNCHER" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=CTF Notifier
GenericName=CTF Browser
Comment=Browse active CTFs worldwide and get reward alerts
Exec="$PY" "$DIR/ctf_notifier.py" --gui
Icon=$ICON
Terminal=false
Categories=Network;Security;
Keywords=CTF;security;hacking;OSCP;capture the flag;
StartupNotify=true
EOF
chmod +x "$LAUNCHER"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
echo "==> App launcher installed: $LAUNCHER"

# ---- desktop icon (double-click to open the GUI) ---------------------------
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
[ -n "$DESKTOP_DIR" ] || DESKTOP_DIR="$HOME/Desktop"
mkdir -p "$DESKTOP_DIR"
DESK_ICON="$DESKTOP_DIR/CTF Notifier.desktop"
cp "$LAUNCHER" "$DESK_ICON"
chmod +x "$DESK_ICON"
# mark trusted so GNOME/Nautilus/XFCE launch it without an "untrusted" prompt
gio set "$DESK_ICON" metadata::trusted true 2>/dev/null || true
gio set "$DESK_ICON" metadata::xfce-exe-checksum "$(sha256sum "$DESK_ICON" | cut -d' ' -f1)" 2>/dev/null || true
echo "==> Desktop icon placed: $DESK_ICON"

# ---- autostart entry (background notifier in the tray) ---------------------
AUTODIR="$HOME/.config/autostart"
mkdir -p "$AUTODIR"
cat > "$AUTODIR/ctf-notifier.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=CTF Notifier (background)
Comment=Tray notifier for CTFs with rewards (prizes / vouchers / cert bundles)
Exec=sh -c 'sleep 15; exec "$PY" "$DIR/ctf_notifier.py"'
Icon=$ICON
Terminal=false
X-GNOME-Autostart-enabled=true
StartupNotify=false
EOF
echo "==> Autostart (tray notifier) registered: $AUTODIR/ctf-notifier.desktop"

echo
echo "Done."
echo "  - Double-click the 'CTF Notifier' icon on your Desktop, or find it in your"
echo "    Applications menu (Network/Security), to open the browser window."
echo "  - The background tray notifier also auto-starts at your next login."
echo
echo "Manual commands if you want them:"
echo "  - Browse CTFs (window):  $PY $DIR/ctf_notifier.py --gui"
echo "  - Test a notification:   $PY $DIR/ctf_notifier.py --test-notify"
echo "  - Start tray now:        $PY $DIR/ctf_notifier.py &"
