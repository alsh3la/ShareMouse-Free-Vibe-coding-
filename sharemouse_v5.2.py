#!/usr/bin/env python3
"""
ShareMouse Free  –  v2  (Windows-optimised)
============================================
Share mouse & keyboard across LAN computers.

Usage
-----
  python sharemouse.py                        → GUI (default)
  python sharemouse.py server                 → headless server
  python sharemouse.py client <server_ip>     → headless client

Requirements
------------
  pip install pynput pyperclip pystray pillow   (all roles)

Windows extras (auto-used when available)
  pip install pywin32          ← faster low-level input injection

macOS note
----------
  Grant Accessibility to Terminal:
  System Settings → Privacy & Security → Accessibility
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import multiprocessing

import sys, socket, threading, json, time, struct, os, platform, queue, logging

# ── constants ─────────────────────────────────────────────────────────────────
PORT          = 54321
MAGIC         = b"SMOUSE2"          # bumped to avoid mixing v1 / v2 peers
PROTO_VERSION = 2
HEARTBEAT_SEC = 2.0                 # keepalive ping interval
EDGE_PX       = 4                   # pixels from edge that triggers hand-off
RECONNECT_SEC = 3.0

IS_WINDOWS = (platform.system() == "Windows")

# ── UAC auto-elevation (Windows only) ────────────────────────────────────────
# SendInput() is silently blocked by UIPI when the foreground window runs at a
# higher integrity level than this process (e.g. Task Manager, Windhawk, any
# "Run as administrator" app).  Re-launching ourselves elevated at startup
# ensures our process matches the highest integrity level on the desktop so
# injected mouse/keyboard events are never dropped.
if IS_WINDOWS:
    import ctypes as _ctypes
    def _is_admin() -> bool:
        try:
            return bool(_ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    if not _is_admin():
        # Re-launch the same command with UAC elevation and exit this instance.
        import ctypes as _ctypes
        _ctypes.windll.shell32.ShellExecuteW(
            None,               # hwnd
            "runas",            # verb  → triggers UAC prompt
            sys.executable,     # file  (python.exe or the .exe bundle)
            " ".join(f'"{a}"' if " " in a else a for a in sys.argv),
            None,               # working directory (inherit)
            1,                  # SW_SHOWNORMAL
        )
        sys.exit(0)

# ── Windows interactive-desktop attachment ────────────────────────────────────
# SendInput() and pynput listeners both require the calling thread to be
# attached to the interactive desktop (WinSta0\Default).  When the process is
# launched by the Task Scheduler (even with RunLevel=Highest and
# LogonType=Interactive) the worker subprocess spawned via multiprocessing
# inherits a NULL or non-interactive window-station token, so all
# SendInput / SetWindowsHookEx calls silently do nothing.
#
# Fix: open WinSta0 + Default desktop by name and call SetThreadDesktop()
# at the very start of every worker process that injects input.

def _win_attach_input_desktop():
    """Attach the calling thread to the interactive desktop.

    Must be called at the top of every worker process so that SendInput and
    pynput hooks reach the correct desktop session.  No-op on non-Windows.
    """
    if not IS_WINDOWS:
        return
    try:
        import ctypes as _d_ctypes
        _u32 = _d_ctypes.windll.user32
        WINSTA_ACCESS  = 0x0000037F
        DESKTOP_ACCESS = 0x000001FF
        hWinSta = _u32.OpenWindowStationW("WinSta0", False, WINSTA_ACCESS)
        if hWinSta:
            _u32.SetProcessWindowStation(hWinSta)
        hDesk = _u32.OpenDesktopW("Default", 0, False, DESKTOP_ACCESS)
        if hDesk:
            _u32.SetThreadDesktop(hDesk)
    except Exception:
        pass   # best-effort; silent if already on the correct desktop

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING,
                    format="%(asctime)s  %(levelname)s  %(message)s")


# ══════════════════════════════════════════════════════════════════════════════
# PROTOCOL
# ══════════════════════════════════════════════════════════════════════════════

def pack_event(event: dict) -> bytes:
    data = json.dumps(event, separators=(",", ":")).encode()
    return MAGIC + struct.pack(">I", len(data)) + data


def unpack_events(buf: bytearray):
    """Return (list_of_events, remaining_buf)."""
    events = []
    mlen   = len(MAGIC)
    while True:
        if len(buf) < mlen + 4:
            break
        if buf[:mlen] != MAGIC:
            buf = buf[1:]          # re-sync
            continue
        length = struct.unpack(">I", buf[mlen:mlen + 4])[0]
        total  = mlen + 4 + length
        if len(buf) < total:
            break
        payload = buf[mlen + 4 : total]
        buf = buf[total:]
        try:
            events.append(json.loads(payload.decode()))
        except Exception:
            pass
    return events, buf


# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS LOW-LEVEL INPUT  (ctypes  –  no pywin32 required)
# ══════════════════════════════════════════════════════════════════════════════

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _user32   = ctypes.windll.user32
    _kernel32 = ctypes.windll.kernel32

    # ── server resolution cache (filled from hello handshake) ─────────────────
    _server_res = [0, 0]

    # ── SendInput structures ──────────────────────────────────────────────────
    # WHY SendInput instead of the legacy mouse_event():
    #
    #   mouse_event() sends MOVE and BUTTON as two separate, non-atomic calls.
    #   Between those two calls Windows performs its hit-test and drag-start
    #   check (WM_LBUTTONDOWN position, OLE DoDragDrop threshold, window-caption
    #   drag detection).  The button therefore fires before the cursor is
    #   registered at the injected position → drag silently misfires or
    #   the cursor freezes as a stuck drag-capture is created.
    #
    #   SendInput() lets us batch [MOVE, BUTTON] into ONE atomic kernel call.
    #   Windows processes the entire batch before servicing any other input,
    #   so hit-testing always uses the correct cursor coordinate and drag works.

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx",          ctypes.c_long),
            ("dy",          ctypes.c_long),
            ("mouseData",   ctypes.c_ulong),
            ("dwFlags",     ctypes.c_ulong),
            ("time",        ctypes.c_ulong),
            ("dwExtraInfo", ctypes.c_size_t),   # ULONG_PTR – 4 B x86 / 8 B x64
        ]

    class KEYBDINPUT(ctypes.Structure):
        # Use SendInput (INPUT_KEYBOARD) instead of legacy keybd_event().
        # keybd_event() is silently dropped when an elevated process injects
        # into a Medium-integrity foreground window.  SendInput goes through
        # the raw-input stack (same path as a physical keyboard) which is
        # UIPI-exempt and works across all integrity levels.
        _fields_ = [
            ("wVk",         wintypes.WORD),
            ("wScan",       wintypes.WORD),
            ("dwFlags",     wintypes.DWORD),
            ("time",        wintypes.DWORD),
            ("dwExtraInfo", ctypes.c_size_t),
        ]

    class _INPUTData(ctypes.Union):
        _fields_ = [
            ("mi", MOUSEINPUT),
            ("ki", KEYBDINPUT),
        ]

    class INPUT(ctypes.Structure):
        _anonymous_ = ("_data",)
        _fields_ = [
            ("type",  ctypes.c_ulong),
            ("_data", _INPUTData),
        ]

    # c_void_p lets us pass both ctypes.byref() and array objects without cast
    _user32.SendInput.restype  = ctypes.c_uint
    _user32.SendInput.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_int]

    _INPUT_SZ = ctypes.sizeof(INPUT)

    # MOUSEEVENTF flag constants
    _MEF_MOVE  = 0x0001
    _MEF_ABS   = 0x8000
    _MEF_MABS  = _MEF_MOVE | _MEF_ABS   # absolute-position update
    _MEF_WHEEL = 0x0800

    # Last injected normalised position (0–65535).
    # Updated by every _win_move_absolute so _win_click can re-confirm it
    # in the same SendInput batch as the button event (the drag fix).
    _last_inj = [32767, 32767]

    def _make_mi(dx: int, dy: int, flags: int, data: int = 0) -> "INPUT":
        inp = INPUT()
        inp.type           = 0   # INPUT_MOUSE
        inp.mi.dx          = dx
        inp.mi.dy          = dy
        inp.mi.mouseData   = data
        inp.mi.dwFlags     = flags
        inp.mi.time        = 0
        inp.mi.dwExtraInfo = 0
        return inp

    def _win_screen_size():
        return (_user32.GetSystemMetrics(0),
                _user32.GetSystemMetrics(1))

    def _win_move_absolute(x, y):
        # Virtual desktop: origin (can be negative) + full dimensions.
        vdw = _user32.GetSystemMetrics(78)   # SM_CXVIRTUALSCREEN  (total width)
        vdh = _user32.GetSystemMetrics(79)   # SM_CYVIRTUALSCREEN  (total height)
        vdx = _user32.GetSystemMetrics(76)   # SM_XVIRTUALSCREEN   (left origin, ≤ 0)
        vdy = _user32.GetSystemMetrics(77)   # SM_YVIRTUALSCREEN   (top  origin, ≤ 0)

        if vdw <= 0 or vdh <= 0:
            # GetSystemMetrics returned garbage — single-monitor safe fallback.
            csw, csh = _win_screen_size()
            ssw = _server_res[0] or csw
            ssh = _server_res[1] or csh
            nx = max(0, min(65535, int(x / ssw * 65535)))
            ny = max(0, min(65535, int(y / ssh * 65535)))
        else:
            # ── Unified mapping ──────────────────────────────────────────────
            # ssw/ssh: the coordinate space the server sends coords in.
            #   • Set from hello handshake (server's own screen/virtual-desktop size).
            #   • Falls back to client's virtual desktop width if server didn't tell us.
            ssw = _server_res[0] or vdw
            ssh = _server_res[1] or vdh

            # mw/mh: the pixel dimensions of the destination region on THIS client.
            #   • Offset mode (Display 2 selected): mw/mh = that monitor's w/h.
            #   • Span mode (offset=0,0):           mw/mh = full virtual desktop.
            if _monitor_offset[0] == 0 and _monitor_offset[1] == 0 and _monitor_wh[0] == 0:
                # SPAN — destination is the full virtual desktop.
                mw = vdw
                mh = vdh
            else:
                # TARGET MONITOR — destination is one specific display.
                mw = _monitor_wh[0] or vdw
                mh = _monitor_wh[1] or vdh

            ox = _monitor_offset[0]   # monitor left edge on virtual desktop
            oy = _monitor_offset[1]   # monitor top  edge on virtual desktop

            # Map: server fraction → destination pixel → virtual-desktop pixel.
            #   fraction_x = x / ssw
            #   dest_pixel  = ox + fraction_x * mw
            px = ox + (x / ssw * mw)
            py = oy + (y / ssh * mh)

            # Normalise virtual-desktop pixel → SendInput [0..65535].
            # With MOUSEEVENTF_VIRTUALDESK the range spans from (vdx,vdy) to
            # (vdx+vdw, vdy+vdh), so subtract the virtual origin first.
            nx = max(0, min(65535, int((px - vdx) * 65535 / vdw)))
            ny = max(0, min(65535, int((py - vdy) * 65535 / vdh)))

        _last_inj[0] = nx
        _last_inj[1] = ny
        # MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
        inp = _make_mi(nx, ny, _MEF_MABS | 0x4000)
        _user32.SendInput(1, ctypes.byref(inp), _INPUT_SZ)

    _BTN_FLAGS = {
        ("left",   True):  0x0002,   # MOUSEEVENTF_LEFTDOWN
        ("left",   False): 0x0004,   # MOUSEEVENTF_LEFTUP
        ("right",  True):  0x0008,   # MOUSEEVENTF_RIGHTDOWN
        ("right",  False): 0x0010,   # MOUSEEVENTF_RIGHTUP
        ("middle", True):  0x0020,   # MOUSEEVENTF_MIDDLEDOWN
        ("middle", False): 0x0040,   # MOUSEEVENTF_MIDDLEUP
    }

    def _win_click(button, pressed):
        flag = _BTN_FLAGS.get((button, pressed))
        if not flag:
            return
        # THE DRAG FIX: send [MOVE → current pos] + [BUTTON] as one atomic
        # SendInput batch (2 elements).  Windows processes both before any
        # other input, so hit-testing, OLE drag-start, and window-caption
        # drag detection all see the cursor at the correct coordinate.
        # VIRTUALDESK flag is required so the re-confirm MOVE also maps
        # across the full virtual desktop (not just the primary monitor).
        arr = (INPUT * 2)()
        arr[0] = _make_mi(_last_inj[0], _last_inj[1], _MEF_MABS | 0x4000)
        arr[1] = _make_mi(0, 0, flag)
        _user32.SendInput(2, arr, _INPUT_SZ)

    def _win_scroll(dy):
        # MOUSEEVENTF_WHEEL; delta = 120 per detent, signed reinterp as DWORD
        delta = ctypes.c_ulong(int(dy * 120)).value
        inp = _make_mi(0, 0, _MEF_WHEEL, delta)
        _user32.SendInput(1, ctypes.byref(inp), _INPUT_SZ)

    # VK code table for pynput Key.* names
    # NOTE: "cmd" / "cmd_r" are intentionally absent — they are handled
    # by the _MAC_NOKEY guard in _win_key() so Ctrl is released cleanly.
    _VK_MAP = {
        "space":0x20,"enter":0x0D,"tab":0x09,"backspace":0x08,
        "delete":0x2E,"escape":0x1B,"up":0x26,"down":0x28,
        "left":0x25,"right":0x27,"home":0x24,"end":0x23,
        "page_up":0x21,"page_down":0x22,"insert":0x2D,
        "caps_lock":0x14,"shift":0x10,"ctrl":0x11,"alt":0x12,
        "shift_l":0xA0,"shift_r":0xA1,
        "ctrl_l":0xA2,"ctrl_r":0xA3,"alt_l":0xA4,"alt_r":0xA5,
        # Mac Option key variant
        "alt_gr":0xA5,
        # Function keys F1-F20
        **{f"f{n}": 0x6F + n for n in range(1, 21)},
        # Extra keys
        "num_lock":0x90,"scroll_lock":0x91,"pause":0x13,
        "print_screen":0x2C,"snapshot":0x2C,
    }

    # ── Modifier bitmask constants (matches Swift modifierBitmask()) ─────────
    # bit 0 = Shift, bit 1 = Ctrl, bit 2 = Alt, bit 3 = Cmd/Win
    # NOTE: bit 3 (Cmd) is never reached here because _translate_mods_for_windows()
    # converts it to bit 1 (Ctrl) *before* _win_press_mods() is called.
    # We keep the entry commented out to document the design intent.
    _MOD_VK_PAIRS = [
        (0x01, 0xA0),   # Shift   → VK_LSHIFT
        (0x02, 0xA2),   # Control → VK_LCONTROL
        (0x04, 0xA4),   # Alt     → VK_LMENU
        # (0x08, 0x5B), # Cmd/Win → suppressed; handled by _translate_mods_for_windows
    ]

    # ── Mac→Windows shortcut translation ─────────────────────────────────────
    # When a macOS server sends ⌘+key (e.g. ⌘C, ⌘V, ⌘X, ⌘A, ⌘Z, ⌘S …),
    # bit 3 of the modifier bitmask is set (Cmd).  On Windows, the equivalent
    # application shortcut uses Ctrl, not Win.  Win+C / Win+V / Win+X are
    # Windows-Shell commands (Action Center, clipboard history, Start-context)
    # and would NOT reach the foreground application at all.
    #
    # Translation rule (applied only on the Windows client side):
    #   • If bit 3 (Cmd) is set → replace it with bit 1 (Ctrl)
    #   • If bit 1 (Ctrl) is already set at the same time, they merge cleanly
    #     (Ctrl stays Ctrl; only the Win key injection is suppressed).
    #
    # This makes ⌘C → Ctrl+C, ⌘V → Ctrl+V, ⌘X → Ctrl+X, ⌘A → Ctrl+A,
    # ⌘Z → Ctrl+Z, ⌘S → Ctrl+S, ⌘W → Ctrl+W, ⌘T → Ctrl+T, etc.
    #
    # The mapping is intentionally one-way (Mac→Win).  When Windows is the
    # server the modifier bitmask comes from pynput which already emits
    # Ctrl (bit 1) for Ctrl keys; bit 3 is never set in that direction.

    def _translate_mods_for_windows(mods: int) -> int:
        """Remap Mac ⌘ (bit 3) → Windows Ctrl (bit 1) in the modifier bitmask."""
        if mods & 0x08:                 # Cmd bit set
            mods = (mods & ~0x08) | 0x02   # clear Cmd, ensure Ctrl
        return mods

    # KEYEVENTF flag constants
    _KEF_KEYUP   = 0x0002   # KEYEVENTF_KEYUP
    _KEF_UNICODE = 0x0004   # KEYEVENTF_UNICODE

    def _make_ki(vk: int, scan: int, flags: int) -> "INPUT":
        """Build an INPUT struct for a keyboard event (INPUT_KEYBOARD = 1)."""
        inp = INPUT()
        inp.type        = 1   # INPUT_KEYBOARD
        inp.ki.wVk      = vk
        inp.ki.wScan    = scan
        inp.ki.dwFlags  = flags
        inp.ki.time     = 0
        inp.ki.dwExtraInfo = 0
        return inp

    def _send_ki(vk: int, scan: int, flags: int):
        """Send a single keyboard INPUT via SendInput (UIPI-exempt)."""
        inp = _make_ki(vk, scan, flags)
        _user32.SendInput(1, ctypes.byref(inp), _INPUT_SZ)

    def _win_press_mods(mods: int, down: bool):
        """Press or release modifier keys via SendInput."""
        flags = _KEF_KEYUP if not down else 0
        for bit, vk in _MOD_VK_PAIRS:
            if mods & bit:
                _send_ki(vk, 0, flags)

    # Additional Mac special-key names that have no Windows equivalent.
    # Receiving these as bare key events is a no-op, but we must still
    # honour the modifier release so Ctrl/Shift/Alt don't get stuck.
    _MAC_NOKEY = frozenset({
        "Key.cmd", "Key.cmd_r",   # ⌘ – translated to Ctrl via mods bitmask
        "Key.fn",                 # fn – no VK equivalent
        "Key.media_play_pause", "Key.media_volume_up", "Key.media_volume_down",
        "Key.media_next", "Key.media_previous",
        "Key.num_lock", "Key.scroll_lock",
    })

    def _win_key(k, pressed, mods: int = 0):
        """Inject a key event via SendInput across all integrity levels.

        Uses SendInput (INPUT_KEYBOARD) instead of the legacy keybd_event()
        so keyboard injection works whether this process is elevated or not.
        """
        mods = _translate_mods_for_windows(mods)

        if k in _MAC_NOKEY:
            # The physical key has no Windows equivalent, but if this is a
            # key-UP we must still release any modifiers that were pressed
            # down by the matching key-DOWN (e.g. Cmd→Ctrl was injected on
            # press; we must release it on release or Ctrl gets stuck).
            if not pressed and mods:
                _win_press_mods(mods, down=False)
            return

        flags_up = _KEF_KEYUP if not pressed else 0

        if pressed and mods:
            _win_press_mods(mods, down=True)

        if k and len(k) == 1:
            if mods and 0x20 <= ord(k) <= 0x7E:
                _send_ki(ord(k.upper()), 0, flags_up)
            else:
                _send_ki(0, ord(k), _KEF_UNICODE | flags_up)
        else:
            name = k.replace("Key.", "").lower()
            vk   = _VK_MAP.get(name)
            if vk:
                _send_ki(vk, 0, flags_up)

        if not pressed and mods:
            _win_press_mods(mods, down=False)

    def _win_get_cursor_pos():
        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
        pt = POINT()
        _user32.GetCursorPos(ctypes.byref(pt))
        return pt.x, pt.y

    def _win_hide_cursor():
        _user32.ShowCursor(False)

    def _win_show_cursor():
        _user32.ShowCursor(True)

    # ── dual-display / monitor enumeration ────────────────────────────────────
    class MONITORINFOEX(ctypes.Structure):
        _fields_ = [
            ("cbSize",      wintypes.DWORD),
            ("rcMonitor",   wintypes.RECT),
            ("rcWork",      wintypes.RECT),
            ("dwFlags",     wintypes.DWORD),
            ("szDevice",    ctypes.c_wchar * 32),
        ]

    _MonitorEnumProc = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM
    )

    def _win_get_monitors():
        """Return list of dicts describing each monitor.
        Each dict: {index, x, y, w, h, work_x, work_y, work_w, work_h,
                    primary, device, label}
        """
        monitors = []

        def _cb(hmon, hdc, lprect, lparam):
            mi = MONITORINFOEX()
            mi.cbSize = ctypes.sizeof(MONITORINFOEX)
            _user32.GetMonitorInfoW(hmon, ctypes.byref(mi))
            r  = mi.rcMonitor
            wr = mi.rcWork
            monitors.append({
                "index":   len(monitors),
                "x": r.left,  "y": r.top,
                "w": r.right  - r.left,
                "h": r.bottom - r.top,
                "work_x": wr.left,  "work_y": wr.top,
                "work_w": wr.right  - wr.left,
                "work_h": wr.bottom - wr.top,
                "primary": bool(mi.dwFlags & 1),
                "device":  mi.szDevice,
                "label":   f"Display {len(monitors) + 1}",
            })
            return True

        cb = _MonitorEnumProc(_cb)
        _user32.EnumDisplayMonitors(None, None, cb, 0)
        # Sort by X position so left display is always index 0
        monitors.sort(key=lambda m: (m["x"], m["y"]))
        for i, m in enumerate(monitors):
            m["index"] = i
            m["label"] = f"Display {i + 1}" + (" ★" if m["primary"] else "")
        return monitors

    def _win_warp_to_monitor(mon: dict, edge: str = "center"):
        """Move cursor to the specified position on a monitor.
        edge: 'center' | 'left' | 'right' | 'top' | 'bottom'
        """
        if edge == "center":
            tx = mon["x"] + mon["w"] // 2
            ty = mon["y"] + mon["h"] // 2
        elif edge == "left":
            tx = mon["x"] + 4
            ty = mon["y"] + mon["h"] // 2
        elif edge == "right":
            tx = mon["x"] + mon["w"] - 4
            ty = mon["y"] + mon["h"] // 2
        elif edge == "top":
            tx = mon["x"] + mon["w"] // 2
            ty = mon["y"] + 4
        elif edge == "bottom":
            tx = mon["x"] + mon["w"] // 2
            ty = mon["y"] + mon["h"] - 4
        else:
            tx = mon["x"] + mon["w"] // 2
            ty = mon["y"] + mon["h"] // 2
        _user32.SetCursorPos(tx, ty)

    def _win_set_monitor_as_client_target(mon: dict):
        """Set the monitor offset so _win_move_absolute maps incoming server
        coordinates onto the correct display on the virtual desktop.

        We do NOT touch _server_res here — that holds the server's own screen
        resolution from the hello handshake and must stay accurate so that
        coordinate fractions are correct.  The offset and monitor size are all we need:

            virtual_pixel = monitor_origin + (server_pixel / server_res) * monitor_size
        """
        _monitor_offset[0] = mon["x"]
        _monitor_offset[1] = mon["y"]
        _monitor_wh[0]     = mon["w"]
        _monitor_wh[1]     = mon["h"]

    def _win_reset_to_span():
        """Clear offset — coordinates map across the full virtual desktop."""
        _monitor_offset[0] = 0
        _monitor_offset[1] = 0
        _monitor_wh[0]     = 0
        _monitor_wh[1]     = 0

    # [x_offset, y_offset] – target monitor origin on virtual desktop
    _monitor_offset = [0, 0]
    # [w, h] – target monitor pixel dimensions (used when offset mode active)
    _monitor_wh     = [0, 0]



# ══════════════════════════════════════════════════════════════════════════════
# CLIPBOARD HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _clip_get() -> str | None:
    try:
        import pyperclip
        return pyperclip.paste()
    except Exception:
        return None

def _clip_set(text: str):
    try:
        import pyperclip
        pyperclip.copy(text)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# SERVER WORKER
# ══════════════════════════════════════════════════════════════════════════════

def _server_worker(log_queue, stop_event, paused_event=None,
                   disable_keyboard_event=None):  # disable_keyboard_event unused by server
    """
    Capture local mouse/keyboard; broadcast to all connected clients.
    Also implements:
      • edge-detection  – when cursor reaches screen edge, lock it there
        and flag that input is being forwarded to the active client.
      • heartbeat pings to detect dead connections early.
      • clipboard sync  – when local clipboard changes, push to all clients.
      • screen-layout handshake (server sends its own resolution on connect).
    """

    def log(msg):
        try:
            log_queue.put_nowait(f"[SERVER] {msg}")
        except Exception:
            pass

    # Attach this worker process to the interactive desktop so that pynput
    # hooks (SetWindowsHookEx) work correctly when launched via Task Scheduler.
    _win_attach_input_desktop()
    log("Desktop session attached (WinSta0\\Default).")

    # ── shared state ──────────────────────────────────────────────────────────
    clients      = []          # list of socket objects
    clients_lock = threading.Lock()
    forwarding   = threading.Event()   # True → input goes to client not local
    mouse_locked = threading.Event()   # True → cursor is locked; clicks do NOT unlock
    last_clip    = [_clip_get()]

    # Virtual cursor accumulator while mouse is locked (mirrors Swift lockedCursorX/Y).
    # Tracks the logical position sent to the client even though the physical cursor is
    # pinned.  Written only from pynput callbacks (single thread) so no extra lock needed.
    locked_cursor = [0.0, 0.0]   # [x, y] in server screen pixels

    # Modifier-key tracking for Ctrl+Alt+K lock-toggle hotkey
    _pressed_mods = set()

    # ── broadcast ─────────────────────────────────────────────────────────────
    def broadcast(event, exclude=None):
        data = pack_event(event)
        dead = []
        with clients_lock:
            for c in clients:
                if c is exclude:
                    continue
                try:
                    c.sendall(data)
                except Exception:
                    dead.append(c)
            for c in dead:
                log(f"Removed dead client")
                clients.remove(c)

    # ── Windows Firewall helper ────────────────────────────────────────────────
    def _ensure_firewall_rule():
        """
        Add an inbound TCP allow-rule for PORT so Windows doesn't actively
        refuse connections (WinError 10061).  Silently no-ops on macOS/Linux
        or when the rule already exists.  Requires the process to be running
        as Administrator (or UAC elevation).
        """
        if not IS_WINDOWS:
            return
        import subprocess
        rule_name = f"ShareMouse TCP {PORT}"
        # Check whether the rule already exists
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True, text=True
        )
        if "No rules match" in check.stdout or check.returncode != 0:
            result = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    f"localport={PORT}",
                    "profile=private,domain",
                    "enable=yes",
                ],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                log(f"✓ Windows Firewall: inbound TCP {PORT} allowed")
            else:
                log(f"⚠ Firewall rule failed (run as Administrator to fix): {result.stderr.strip()}")
                log(f"  Manual fix: netsh advfirewall firewall add rule name=\"{rule_name}\" "
                    f"dir=in action=allow protocol=TCP localport={PORT}")
        else:
            log(f"✓ Windows Firewall rule already present for port {PORT}")

    _ensure_firewall_rule()

    # ── accept loop ───────────────────────────────────────────────────────────
    def accept_loop():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", PORT))
        srv.listen(8)
        srv.settimeout(1.0)
        log(f"Listening on :{PORT}")

        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            ip = addr[0]
            log(f"Client connected: {ip}")

            # Send handshake: server resolution + proto version + OS hint
            # Send virtual-desktop dimensions (all monitors combined) so the
            # Windows client can correctly normalise multi-monitor coordinates.
            if IS_WINDOWS:
                sw = _user32.GetSystemMetrics(78) or _win_screen_size()[0]  # SM_CXVIRTUALSCREEN
                sh = _user32.GetSystemMetrics(79) or _win_screen_size()[1]  # SM_CYVIRTUALSCREEN
            else:
                sw, sh = 0, 0
            try:
                conn.sendall(pack_event({
                    "t":     "hello",
                    "proto": PROTO_VERSION,
                    "sw":    sw, "sh": sh,
                    "os":    "windows" if IS_WINDOWS else "mac",
                }))
            except Exception:
                conn.close()
                continue

            with clients_lock:
                clients.append(conn)
            threading.Thread(target=recv_loop, args=(conn, ip), daemon=True).start()
            threading.Thread(target=ping_loop, args=(conn, ip), daemon=True).start()

        srv.close()

    # ── per-client receive (handles pong + clipboard from client) ─────────────
    def recv_loop(conn, ip):
        """
        Blocking read loop – no socket timeout here.
        Liveness is guaranteed by ping_loop; recv returns empty bytes on a
        clean disconnect, and raises OSError on a broken pipe – both are real
        disconnects, not false alarms.
        """
        buf = bytearray()
        try:
            conn.settimeout(None)          # block indefinitely – no false timeouts
            while not stop_event.is_set():
                chunk = conn.recv(4096)
                if not chunk:              # clean EOF from client
                    break
                buf.extend(chunk)
                events, buf = unpack_events(buf)
                for ev in events:
                    t = ev.get("t")
                    if t == "pong":
                        pass               # heartbeat acknowledged
                    elif t == "clip":
                        text = ev.get("text", "")
                        _clip_set(text)
                        last_clip[0] = text
                        log(f"Clipboard synced from client → {len(text)} chars")
                        # Signal GUI to save this remote clip in history
                        try:
                            log_queue.put_nowait({"__clip__": text, "__remote__": True})
                        except Exception:
                            pass
        except OSError:
            pass                           # real broken connection
        finally:
            log(f"Client disconnected: {ip}")
            with clients_lock:
                if conn in clients:
                    clients.remove(conn)
            try:
                conn.close()
            except Exception:
                pass

    # ── heartbeat to each client ──────────────────────────────────────────────
    def ping_loop(conn, ip):
        """
        Sends a ping every HEARTBEAT_SEC seconds.
        Exits cleanly when the connection is gone – recv_loop's finally block
        handles the cleanup, so ping_loop just needs to stop sending.
        """
        while not stop_event.is_set():
            time.sleep(HEARTBEAT_SEC)
            with clients_lock:
                alive = conn in clients
            if not alive:
                break                      # recv_loop already cleaned up
            try:
                conn.sendall(pack_event({"t": "ping"}))
            except OSError:
                break

    # ── clipboard watch ───────────────────────────────────────────────────────
    # Windows / macOS Python side: poll the local clipboard every second.
    # On macOS the Swift host (ClipboardManager) already sends "clip" packets
    # to connected peers whenever the user copies something — this thread is
    # redundant when running as a pure client of the Swift server.  It is kept
    # here so the Python process can also act as a standalone server that
    # forwards Windows clipboard changes to Swift clients.
    def clip_watch():
        while not stop_event.is_set():
            time.sleep(1.0)
            cur = _clip_get()
            if cur and cur != last_clip[0]:
                last_clip[0] = cur
                broadcast({"t": "clip", "text": cur})
                log("Clipboard changed locally → broadcasting to all clients")
                # Signal GUI to persist this local clip in history
                try:
                    log_queue.put_nowait({"__clip__": cur, "__remote__": False})
                except Exception:
                    pass

    threading.Thread(target=accept_loop, daemon=True).start()
    threading.Thread(target=clip_watch,  daemon=True).start()

    # ── pynput listeners ──────────────────────────────────────────────────────
    try:
        from pynput import mouse, keyboard
    except ImportError as e:
        log(f"ERROR importing pynput: {e}")
        log("Fix: pip install pynput")
        stop_event.wait()
        return

    # ── edge detection (Windows only for now) ─────────────────────────────────
    def check_edge(x, y):
        """Return True if cursor is at a triggerable screen edge.

        Uses the full virtual desktop width so that a multi-monitor server
        triggers handoff only at the outermost edge, not at the right edge
        of the primary display.
        """
        if not IS_WINDOWS:
            return False
        vdx = _user32.GetSystemMetrics(76)   # SM_XVIRTUALSCREEN (left-most x, can be negative)
        vdw = _user32.GetSystemMetrics(78)   # SM_CXVIRTUALSCREEN (full width)
        right_edge = vdx + vdw - 1
        return x <= (vdx + EDGE_PX) or x >= (right_edge - EDGE_PX)

    def on_move(x, y):
        if mouse_locked.is_set():
            # While locked the physical cursor is pinned; accumulate raw HID deltas
            # into the virtual cursor and broadcast that position to the client.
            # pynput gives us absolute coords on the pinned position — we need the
            # delta relative to our last known locked position.
            dx = x - locked_cursor[0]
            dy = y - locked_cursor[1]
            if dx == 0 and dy == 0:
                return   # skip zero-delta warp-echo events
            if IS_WINDOWS:
                # Clamp to the full virtual desktop so multi-monitor servers can
                # reach Display 2 while locked (old code clamped to primary only).
                vdx = _user32.GetSystemMetrics(76)   # SM_XVIRTUALSCREEN
                vdy = _user32.GetSystemMetrics(77)   # SM_YVIRTUALSCREEN
                vdw = _user32.GetSystemMetrics(78)   # SM_CXVIRTUALSCREEN
                vdh = _user32.GetSystemMetrics(79)   # SM_CYVIRTUALSCREEN
                locked_cursor[0] = max(float(vdx), min(float(vdx + vdw - 1), locked_cursor[0] + dx))
                locked_cursor[1] = max(float(vdy), min(float(vdy + vdh - 1), locked_cursor[1] + dy))
            else:
                locked_cursor[0] += dx
                locked_cursor[1] += dy
            broadcast({"t": "mm", "x": locked_cursor[0], "y": locked_cursor[1]})
            return
        if check_edge(x, y) and not forwarding.is_set():
            forwarding.set()
            log("Edge reached -> forwarding to client")
            broadcast({"t": "focus", "active": True})
            if IS_WINDOWS:
                _win_hide_cursor()
        broadcast({"t": "mm", "x": x, "y": y})

    def on_click(x, y, b, pressed):
        from pynput.mouse import Button
        # Use virtual cursor position when locked so the client gets the correct coords.
        cx = locked_cursor[0] if mouse_locked.is_set() else x
        cy = locked_cursor[1] if mouse_locked.is_set() else y
        broadcast({"t": "mc", "x": cx, "y": cy, "b": b.name, "p": pressed})
        # Only release forwarding on LEFT-click-up when mouse is NOT locked.
        # When locked only the Ctrl+Alt+K hotkey may unlock.
        if not pressed and (b == Button.left) and forwarding.is_set() and not mouse_locked.is_set():
            forwarding.clear()
            if IS_WINDOWS:
                _win_show_cursor()
        # FREEZE FIX: suppress ALL clicks from reaching macOS while forwarding
        # or mouse-locked.  Without suppression a right-click on the Mac opens a
        # context menu which blocks pynput's CGEvent tap from receiving mouseMoved
        # events → no mm packets reach the Windows client → cursor appears frozen.
        # Returning False from a pynput callback tells pynput to consume the event.
        if forwarding.is_set() or mouse_locked.is_set():
            return False

    def on_scroll(x, y, dx, dy):
        broadcast({"t": "ms", "x": x, "y": y, "dx": dx, "dy": dy})

    def on_press(key):
        from pynput.keyboard import Key
        # Track modifier keys for hotkey detection AND bitmask encoding.
        # We track Shift/Ctrl/Alt/Cmd (macOS) so the modifier bitmask can be
        # sent in every kp/kr packet, enabling the Windows client to translate
        # ⌘+key → Ctrl+key automatically via _translate_mods_for_windows().
        if key in (Key.shift,   Key.shift_l,   Key.shift_r):
            _pressed_mods.add(key)
        if key in (Key.ctrl,    Key.ctrl_l,    Key.ctrl_r):
            _pressed_mods.add(key)
        if key in (Key.alt,     Key.alt_l,     Key.alt_r):
            _pressed_mods.add(key)
        if key in (Key.cmd,     Key.cmd_r) if hasattr(Key, "cmd") else ():
            _pressed_mods.add(key)

        # Ctrl+Alt+K  →  toggle mouse lock
        ctrl_held  = any(k in _pressed_mods for k in (Key.ctrl, Key.ctrl_l, Key.ctrl_r))
        alt_held   = any(k in _pressed_mods for k in (Key.alt,  Key.alt_l,  Key.alt_r))
        is_K = getattr(key, "char", None) in ("k", "K")
        if ctrl_held and alt_held and is_K:
            if mouse_locked.is_set():
                mouse_locked.clear()
                log("Mouse unlocked (Ctrl+Alt+K)")
                if IS_WINDOWS:
                    _win_show_cursor()
            else:
                if IS_WINDOWS:
                    cx, cy = _win_get_cursor_pos()
                else:
                    cx, cy = 0.0, 0.0
                locked_cursor[0] = float(cx)
                locked_cursor[1] = float(cy)
                mouse_locked.set()
                log("Mouse locked (Ctrl+Alt+K) — cursor pinned")
                if IS_WINDOWS:
                    _win_hide_cursor()
            return   # don't forward the hotkey to clients

        # Build modifier bitmask matching the Swift modifierBitmask() encoding:
        #   bit 0 = Shift, bit 1 = Ctrl, bit 2 = Alt, bit 3 = Cmd/Win
        # This is sent in the "m" field so the Windows client can call
        # _translate_mods_for_windows() and inject the right modifier VKs.
        def _mod_bitmask():
            m = 0
            if any(k in _pressed_mods for k in (Key.shift, Key.shift_l, Key.shift_r)):
                m |= 0x01
            if any(k in _pressed_mods for k in (Key.ctrl,  Key.ctrl_l,  Key.ctrl_r)):
                m |= 0x02
            if any(k in _pressed_mods for k in (Key.alt,   Key.alt_l,   Key.alt_r)):
                m |= 0x04
            _cmd_keys = []
            if hasattr(Key, "cmd"):   _cmd_keys.append(Key.cmd)
            if hasattr(Key, "cmd_r"): _cmd_keys.append(Key.cmd_r)
            if any(k in _pressed_mods for k in _cmd_keys):
                m |= 0x08
            return m

        # Resolve the key string.  On macOS, when ⌘ is held pynput may set
        # key.char to a control character (e.g. ⌘C → '\x03') because the OS
        # maps Cmd+letter to ASCII control codes at the HID layer.  We recover
        # the base printable character by masking out control-char offsets:
        #   '\x01'–'\x1A'  →  'a'–'z'  (Cmd+A through Cmd+Z)
        # This ensures the Windows client receives "c" (not "\x03") so that
        # _win_key() can inject the correct Virtual Key code for the letter.
        def _resolve_key(k):
            try:
                ch = k.char
            except AttributeError:
                return str(k)
            if ch is None:
                return str(k)
            # Control-character recovery: Cmd+A=\x01 … Cmd+Z=\x1A
            code = ord(ch)
            if 0x01 <= code <= 0x1A:
                return chr(code + 0x60)   # → 'a'–'z'
            return ch

        k = _resolve_key(key)
        m = _mod_bitmask()
        broadcast({"t": "kp", "k": k, "m": m})

    def on_release(key):
        from pynput.keyboard import Key

        # Build bitmask BEFORE discarding the released key so the release
        # packet still carries the correct (still-held) modifier state.
        def _mod_bitmask_release():
            m = 0
            if any(k in _pressed_mods for k in (Key.shift, Key.shift_l, Key.shift_r)):
                m |= 0x01
            if any(k in _pressed_mods for k in (Key.ctrl,  Key.ctrl_l,  Key.ctrl_r)):
                m |= 0x02
            if any(k in _pressed_mods for k in (Key.alt,   Key.alt_l,   Key.alt_r)):
                m |= 0x04
            _cmd_keys = []
            if hasattr(Key, "cmd"):   _cmd_keys.append(Key.cmd)
            if hasattr(Key, "cmd_r"): _cmd_keys.append(Key.cmd_r)
            if any(k in _pressed_mods for k in _cmd_keys):
                m |= 0x08
            return m

        m = _mod_bitmask_release()
        _pressed_mods.discard(key)

        def _resolve_key(k):
            try:
                ch = k.char
            except AttributeError:
                return str(k)
            if ch is None:
                return str(k)
            code = ord(ch)
            if 0x01 <= code <= 0x1A:
                return chr(code + 0x60)
            return ch

        k = _resolve_key(key)
        broadcast({"t": "kr", "k": k, "m": m})

    try:
        ml = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll)
        kl = keyboard.Listener(on_press=on_press, on_release=on_release)
        ml.start(); kl.start()
        log("Capturing input. Connect clients now.")
    except Exception as e:
        log(f"ERROR starting listeners: {e}")
        if not IS_WINDOWS:
            log("macOS: grant Accessibility in System Settings → Privacy → Accessibility")
        stop_event.wait()
        return

    stop_event.wait()
    try: ml.stop()
    except Exception: pass
    try: kl.stop()
    except Exception: pass
    if IS_WINDOWS:
        _win_show_cursor()
    log("Stopped.")


# ══════════════════════════════════════════════════════════════════════════════
# CLIENT WORKER
# ══════════════════════════════════════════════════════════════════════════════

def _client_worker(server_ip, log_queue, stop_event, paused_event=None,
                   disable_keyboard_event=None):
    """
    Receive events from server and replay them.
    Windows path uses ctypes SendInput (no UAC needed for most apps).
    Falls back to pynput on other platforms.
    """
    def log(msg):
        try:
            log_queue.put_nowait(f"[CLIENT] {msg}")
        except Exception:
            pass

    # Attach this worker process to the interactive desktop so that SendInput
    # reaches the foreground window when launched via Task Scheduler.
    _win_attach_input_desktop()
    log("Desktop session attached (WinSta0\\Default).")

    # ── input back-end selection ──────────────────────────────────────────────
    # Windows: use mouse_event/keybd_event via ctypes (no struct complexity).
    # Other:   use pynput Controller (works on macOS/Linux).

    # Virtual cursor accumulator for iOS delta-based mm packets.
    # iOS sends {"t":"mm","dx":…,"dy":…} (relative moves) instead of
    # absolute coords.  We maintain a virtual position here and convert.
    _vcursor = [960.0, 540.0]   # initialised to screen centre; updated on hello

    if IS_WINDOWS:
        def do_move(x, y):
            _win_move_absolute(x, y)
        def do_click(b, pressed, x=None, y=None):
            # THE DRAG FIX: the mc packet carries the click's own (x, y).
            # Refresh _last_inj via _win_move_absolute (which handles the full
            # virtual-desktop + monitor-offset normalisation) before the atomic
            # [MOVE+BUTTON] batch in _win_click fires.
            if x is not None and y is not None:
                _win_move_absolute(x, y)   # also updates _last_inj correctly
            _win_click(b, pressed)
        def do_scroll(dx, dy):
            _win_scroll(dy)
        def do_key(k, pressed, mods=0):
            _win_key(k, pressed, mods)
        def set_server_res(sw, sh):
            _server_res[0] = sw
            _server_res[1] = sh
            # Re-centre virtual cursor on hello so iOS deltas start sensibly
            if IS_WINDOWS:
                csw, csh = _win_screen_size()
            else:
                csw, csh = sw, sh
            _vcursor[0] = csw / 2.0
            _vcursor[1] = csh / 2.0
    else:
        from pynput.mouse import Button, Controller as MC
        from pynput.keyboard import Key, Controller as KC
        _mc  = MC()
        _kc  = KC()
        _BTN = {"left": Button.left, "right": Button.right, "middle": Button.middle}

        def _pk(k):
            if k and len(k) == 1:
                return k
            name = k.replace("Key.", "")
            try:   return Key[name]
            except: return k

        def do_move(x, y):
            _mc.position = (int(x), int(y))
        def do_click(b, pressed, x=None, y=None):
            # Mirror the Windows drag fix: if the mc packet carries (x, y),
            # warp the cursor there before pressing/releasing so that pynput's
            # Controller sees the correct position (matters for drag start).
            if x is not None and y is not None:
                _mc.position = (int(x), int(y))
            btn = _BTN.get(b, Button.left)
            _mc.press(btn) if pressed else _mc.release(btn)
        def do_scroll(dx, dy):
            _mc.scroll(dx, dy)
        def do_key(k, pressed, mods=0):
            from pynput.keyboard import Key as _Key
            # Modifier bitmask: bit0=Shift, bit1=Ctrl, bit2=Alt, bit3=Cmd
            _MOD_KEYS = [
                (0x01, _Key.shift),
                (0x02, _Key.ctrl),
                (0x04, _Key.alt),
                (0x08, _Key.cmd),
            ]
            if pressed and mods:
                for bit, mod_key in _MOD_KEYS:
                    if mods & bit:
                        try: _kc.press(mod_key)
                        except Exception: pass
            pk = _pk(k)
            try:
                _kc.press(pk) if pressed else _kc.release(pk)
            except Exception:
                pass
            if not pressed and mods:
                for bit, mod_key in _MOD_KEYS:
                    if mods & bit:
                        try: _kc.release(mod_key)
                        except Exception: pass
        def set_server_res(sw, sh):
            pass   # pynput uses absolute screen coords already

    # ── main reconnect loop ───────────────────────────────────────────────────
    # Dead-server detection: track last time we received ANYTHING from the server.
    # If that gap exceeds HEARTBEAT_DEAD_SEC we declare it dead and reconnect.
    # We do NOT use socket.timeout for this – that fires on any quiet moment
    # (e.g. mouse not moving) and causes false disconnect storms.
    HEARTBEAT_DEAD_SEC = HEARTBEAT_SEC * 5   # 10 s — generous, LAN is fast
    last_rx = [time.monotonic()]

    def _watchdog(sock_ref, dead_event):
        """Background thread: sets dead_event if server goes silent too long."""
        while not stop_event.is_set() and not dead_event.is_set():
            time.sleep(1.0)
            if time.monotonic() - last_rx[0] > HEARTBEAT_DEAD_SEC:
                dead_event.set()
                try:
                    sock_ref[0].shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                break

    while not stop_event.is_set():
        sock = None
        dead_event = threading.Event()
        sock_ref   = [None]
        try:
            log(f"Connecting to {server_ip}:{PORT} …")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)            # connect-phase timeout only
            sock.connect((server_ip, PORT))
            sock.settimeout(None)           # blocking recv – no spurious timeouts
            sock_ref[0] = sock
            last_rx[0]  = time.monotonic()
            threading.Thread(target=_watchdog, args=(sock_ref, dead_event),
                             daemon=True).start()
            log("Connected! Receiving input.")
            buf = bytearray()

            while not stop_event.is_set():
                chunk = sock.recv(4096)
                if not chunk:
                    break
                last_rx[0] = time.monotonic()   # reset watchdog timer
                buf.extend(chunk)
                events, buf = unpack_events(buf)
                for ev in events:
                    t = ev.get("t")
                    try:
                        # Check pause state; protocol events always pass through
                        _paused = paused_event is not None and paused_event.is_set()
                        if t == "mm":
                            if not _paused:
                                # iOS sends delta packets {"dx":…,"dy":…}.
                                # Mac/Win servers send absolute {"x":…,"y":…}.
                                # Handle both: accumulate deltas into _vcursor.
                                if "x" in ev and "y" in ev:
                                    do_move(ev["x"], ev["y"])
                                    _vcursor[0] = float(ev["x"])
                                    _vcursor[1] = float(ev["y"])
                                elif "dx" in ev and "dy" in ev:
                                    if IS_WINDOWS:
                                        csw, csh = _win_screen_size()
                                    else:
                                        csw, csh = (_server_res[0] or 1920,
                                                    _server_res[1] or 1080)
                                    _vcursor[0] = max(0.0, min(float(csw - 1),
                                                               _vcursor[0] + float(ev["dx"])))
                                    _vcursor[1] = max(0.0, min(float(csh - 1),
                                                               _vcursor[1] + float(ev["dy"])))
                                    do_move(_vcursor[0], _vcursor[1])
                        elif t == "mc":
                            if not _paused:
                                # BUG FIX: ev.get("x") or _vcursor[0] treats x=0 as falsy,
                                # causing every zero-coord click to land at the virtual cursor
                                # position.  Use explicit None check instead.
                                cx_raw = ev.get("x")
                                cy_raw = ev.get("y")
                                cx = float(cx_raw) if cx_raw is not None else _vcursor[0]
                                cy = float(cy_raw) if cy_raw is not None else _vcursor[1]
                                do_click(ev["b"], ev["p"], cx, cy)
                        elif t == "ms":
                            if not _paused: do_scroll(ev["dx"], ev["dy"])
                        elif t == "kp":
                            if not _paused:
                                _kb_off = (disable_keyboard_event is not None
                                           and disable_keyboard_event.is_set())
                                if not _kb_off:
                                    do_key(ev["k"], True,  ev.get("m", 0))
                        elif t == "kr":
                            if not _paused:
                                _kb_off = (disable_keyboard_event is not None
                                           and disable_keyboard_event.is_set())
                                if not _kb_off:
                                    do_key(ev["k"], False, ev.get("m", 0))
                        elif t == "ping":
                            # Always reply to pings so the server doesn't drop us
                            sock.sendall(pack_event({"t": "pong"}))
                        elif t == "clip":
                            if not _paused:
                                text = ev.get("text", "")
                                _clip_set(text)
                                log(f"Clipboard synced from server → {len(text)} chars")
                                # Signal GUI to save this remote clip in history
                                try:
                                    log_queue.put_nowait({"__clip__": text, "__remote__": True})
                                except Exception:
                                    pass
                        elif t == "hello":
                            sw, sh  = ev.get("sw", 0), ev.get("sh", 0)
                            role    = ev.get("role", "")
                            srv_os  = ev.get("os", "")
                            if sw and sh:
                                set_server_res(sw, sh)
                            role_note = f"  [{role}]" if role else ""
                            os_note   = f"  os={srv_os}" if srv_os else ""
                            log(f"Server proto v{ev.get('proto')}{role_note}{os_note}  "
                                f"resolution {sw}x{sh}")
                            if role == "ios":
                                log("iOS server mode – delta mouse events active")
                            if IS_WINDOWS and srv_os == "mac":
                                log("Mac server detected:")
                                log("  ⌘+key → Ctrl+key  (⌘C=Ctrl+C, ⌘V=Ctrl+V, ⌘Z=Ctrl+Z …)")
                                log("  ⌥ (Option) → Alt")
                                log("  Mac fn / media keys silently suppressed")
                        elif t == "focus":
                            if ev.get("active") and not _paused:
                                log("Focus acquired – this screen is active")
                    except Exception as exc:
                        log(f"EVENT ERROR t={t} ev={ev} → {exc}")

        except OSError as e:
            # Real network error (broken pipe, connection refused, etc.)
            if not stop_event.is_set():
                log(f"Connection lost: {e}. Retrying in {RECONNECT_SEC}s …")
                time.sleep(RECONNECT_SEC)
        except Exception as e:
            # Unexpected error – log it so we can debug, still retry
            if not stop_event.is_set():
                log(f"Unexpected error: {e}. Retrying in {RECONNECT_SEC}s …")
                time.sleep(RECONNECT_SEC)
        finally:
            dead_event.set()    # stop watchdog thread
            if sock:
                try: sock.close()
                except Exception: pass
    log("Stopped.")


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS WRAPPER  (used by GUI)
# ══════════════════════════════════════════════════════════════════════════════

class WorkerProcess:
    def __init__(self, target, args=()):
        self._log_queue            = multiprocessing.Queue()
        self._stop_event           = multiprocessing.Event()
        self._paused_event         = multiprocessing.Event()   # set = paused
        self._disable_keyboard_event = multiprocessing.Event() # set = keyboard disabled
        self._proc = multiprocessing.Process(
            target=target,
            args=args + (self._log_queue, self._stop_event,
                         self._paused_event, self._disable_keyboard_event),
            daemon=True,
        )

    def start(self):
        self._proc.start()

    def stop(self):
        self._stop_event.set()
        self._proc.join(timeout=4)
        if self._proc.is_alive():
            self._proc.terminate()

    def pause(self):
        self._paused_event.set()

    def resume(self):
        self._paused_event.clear()

    @property
    def paused(self):
        return self._paused_event.is_set()

    def disable_keyboard(self):
        self._disable_keyboard_event.set()

    def enable_keyboard(self):
        self._disable_keyboard_event.clear()

    @property
    def keyboard_disabled(self):
        return self._disable_keyboard_event.is_set()

    def drain_logs(self):
        msgs = []
        while True:
            try:   msgs.append(self._log_queue.get_nowait())
            except Exception: break
        return msgs

    @property
    def running(self):
        return self._proc.is_alive()


# ══════════════════════════════════════════════════════════════════════════════
# HEADLESS  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def run_server_headless():
    lq = multiprocessing.Queue()
    se = multiprocessing.Event()
    p  = multiprocessing.Process(target=_server_worker, args=(lq, se), daemon=False)
    p.start()
    print(f"Server running on :{PORT}. Ctrl+C to stop.")
    try:
        while True:
            try:   print(lq.get(timeout=0.5))
            except Exception: pass
    except KeyboardInterrupt:
        se.set(); p.join(3)


def run_client_headless(ip):
    lq = multiprocessing.Queue()
    se = multiprocessing.Event()
    p  = multiprocessing.Process(target=_client_worker, args=(ip, lq, se), daemon=False)
    p.start()
    print(f"Client connecting to {ip}:{PORT}. Ctrl+C to stop.")
    try:
        while True:
            try:   print(lq.get(timeout=0.5))
            except Exception: pass
    except KeyboardInterrupt:
        se.set(); p.join(3)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITY
# ══════════════════════════════════════════════════════════════════════════════

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG  (persist client IP across sessions)
# ══════════════════════════════════════════════════════════════════════════════

# Store config next to the exe (or script) so it persists across runs.
# sys.executable points to the .exe when frozen by PyInstaller;
# __file__ is used as fallback for plain .py runs.
def _config_dir() -> str:
    if getattr(sys, "frozen", False):
        # Running as a PyInstaller bundle — use the folder containing the .exe
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(_config_dir(), "sharemouse_config.json")


def load_config() -> dict:
    """Return the saved config dict, or {} if missing / corrupt."""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def save_config(data: dict):
    """Persist *data* to CONFIG_FILE (merges with existing config)."""
    try:
        existing = load_config()
        existing.update(data)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
    except Exception as exc:
        logging.warning("Could not save config: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# CLIPBOARD HISTORY  (persisted next to exe / script as clipboard_history.json)
# ══════════════════════════════════════════════════════════════════════════════

CLIP_HISTORY_FILE = os.path.join(_config_dir(), "clipboard_history.json")
CLIP_HISTORY_MAX  = 50   # max unpinned entries kept on disk


def _clip_history_load() -> list:
    """Return list of item dicts, newest first.  Each dict has:
       id (str), content (str), ts (float), pinned (bool), remote (bool)
    """
    try:
        with open(CLIP_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def _clip_history_save(items: list):
    try:
        with open(CLIP_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        logging.warning("Could not save clipboard history: %s", exc)


def _clip_history_add(items: list, text: str, remote: bool = False) -> list:
    """Insert *text* at the front (deduplicating), trim unpinned overflow."""
    import uuid as _uuid
    # Remove any existing entry with the same content
    items = [i for i in items if i.get("content") != text]
    items.insert(0, {
        "id":      str(_uuid.uuid4()),
        "content": text,
        "ts":      time.time(),
        "pinned":  False,
        "remote":  remote,
    })
    # Keep all pinned + up to CLIP_HISTORY_MAX unpinned
    pinned   = [i for i in items if i.get("pinned")]
    unpinned = [i for i in items if not i.get("pinned")]
    return pinned + unpinned[:CLIP_HISTORY_MAX]


# ══════════════════════════════════════════════════════════════════════════════
# GUI  v3 — upgraded premium UI
# ══════════════════════════════════════════════════════════════════════════════

def launch_gui():
    try:
        from PyQt6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QPushButton, QLineEdit, QTextEdit, QCheckBox,
            QFrame, QSizePolicy, QScrollArea,
            QSystemTrayIcon, QMenu, QStackedWidget, QInputDialog,
            QGraphicsDropShadowEffect,
        )
        from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, pyqtSignal, QObject
        from PyQt6.QtGui  import (
            QFont, QColor, QPalette, QIcon, QPixmap, QPainter,
            QLinearGradient, QPen, QBrush, QPainterPath, QFontDatabase,
        )
    except ImportError:
        print("PyQt6 not found.  pip install PyQt6")
        print("Headless fallback:")
        print("  python sharemouse.py server")
        print("  python sharemouse.py client <server_ip>")
        return

    import sys as _sys

    # ── palette — refined dark theme ──────────────────────────────────────────
    BG      = "#080810"   # near-black base
    CARD    = "#10101e"   # card surface
    CARD2   = "#18182a"   # elevated card
    CARD3   = "#1f1f35"   # input / subtle
    BORDER  = "#2a2a45"   # border colour
    ACCENT  = "#6C63FF"   # vivid indigo
    ACCENT2 = "#00D4AA"   # teal highlight
    ACCENT3 = "#FF6B9D"   # pink accent
    FG      = "#F0EEFF"   # primary text
    FG2     = "#A8A4C8"   # secondary text
    MUTED   = "#52516A"   # muted / disabled
    SUCCESS = "#23D18B"   # green
    DANGER  = "#FF5370"   # red
    WARN    = "#FFB347"   # amber

    # ── shared state ─────────────────────────────────────────────────────────
    local_ip    = get_local_ip()
    worker      = [None]
    _cfg        = load_config()
    _saved_ip   = _cfg.get("client_ip", "")
    _auto_start = _cfg.get("auto_start", False)

    # ── app setup ────────────────────────────────────────────────────────────
    app = QApplication.instance() or QApplication(_sys.argv)
    app.setStyle("Fusion")

    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window,          QColor(BG))
    pal.setColor(QPalette.ColorRole.WindowText,      QColor(FG))
    pal.setColor(QPalette.ColorRole.Base,            QColor(CARD))
    pal.setColor(QPalette.ColorRole.AlternateBase,   QColor(CARD2))
    pal.setColor(QPalette.ColorRole.Text,            QColor(FG))
    pal.setColor(QPalette.ColorRole.Button,          QColor(CARD2))
    pal.setColor(QPalette.ColorRole.ButtonText,      QColor(FG))
    pal.setColor(QPalette.ColorRole.Highlight,       QColor(ACCENT))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(BG))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(MUTED))
    app.setPalette(pal)

    app.setStyleSheet(f"""
        QMainWindow, QWidget {{ background: {BG}; color: {FG}; }}
        QScrollBar:vertical {{
            background: {CARD2}; width: 6px; border-radius: 3px; border: none;
        }}
        QScrollBar::handle:vertical {{
            background: {BORDER}; border-radius: 3px; min-height: 24px;
        }}
        QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        QToolTip {{
            background: {CARD2}; color: {FG}; border: 1px solid {BORDER};
            padding: 4px 8px; border-radius: 4px;
        }}
    """)

    # ── tray icon ────────────────────────────────────────────────────────────
    def _make_tray_pixmap(size=64):
        px = QPixmap(size, size)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # background circle
        p.setBrush(QColor(CARD2))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(2, 2, size - 4, size - 4)
        # accent ring
        p.setPen(QPen(QColor(ACCENT), 3))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(5, 5, size - 10, size - 10)
        # cursor shape
        p.setBrush(QColor(FG))
        p.setPen(Qt.PenStyle.NoPen)
        cx, cy = size // 2, size // 2
        path = QPainterPath()
        path.moveTo(cx - 8, cy - 10)
        path.lineTo(cx - 8, cy + 10)
        path.lineTo(cx - 2, cy + 4)
        path.lineTo(cx + 4, cy + 14)
        path.lineTo(cx + 8, cy + 12)
        path.lineTo(cx + 2, cy + 2)
        path.lineTo(cx + 10, cy + 2)
        path.closeSubpath()
        p.drawPath(path)
        p.end()
        return px

    # ── helpers ───────────────────────────────────────────────────────────────
    MONO  = QFont("Consolas", 10)
    MONO_S = QFont("Consolas", 9)
    MONO_L = QFont("Consolas", 12)
    MONO_XL = QFont("Consolas", 14, QFont.Weight.Bold)

    def lbl(text, size=10, bold=False, color=FG, parent=None):
        w = QLabel(text, parent)
        f = QFont("Consolas", size)
        f.setBold(bold)
        w.setFont(f)
        w.setStyleSheet(f"color: {color}; background: transparent;")
        return w

    def hline():
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color: {BORDER}; background: {BORDER};")
        line.setFixedHeight(1)
        return line

    # ── main window ───────────────────────────────────────────────────────────
    win = QMainWindow()
    win.setWindowTitle("ShareMouse  v3")
    win.setFixedSize(580, 750)
    win.setWindowIcon(QIcon(_make_tray_pixmap()))

    central = QWidget()
    win.setCentralWidget(central)
    win_layout = QVBoxLayout(central)
    win_layout.setContentsMargins(0, 0, 0, 0)
    win_layout.setSpacing(0)

    # ── top title bar ─────────────────────────────────────────────────────────
    title_bar = QWidget()
    title_bar.setFixedHeight(56)
    title_bar.setStyleSheet(f"""
        QWidget {{
            background: {CARD};
            border-bottom: 1px solid {BORDER};
        }}
    """)
    tb_layout = QHBoxLayout(title_bar)
    tb_layout.setContentsMargins(20, 0, 16, 0)
    tb_layout.setSpacing(10)

    # logo + title
    logo_lbl = QLabel("◈")
    logo_lbl.setFont(QFont("Consolas", 22, QFont.Weight.Bold))
    logo_lbl.setStyleSheet(f"color: {ACCENT}; background: transparent;")

    app_name = QLabel("ShareMouse")
    app_name.setFont(QFont("Consolas", 15, QFont.Weight.Bold))
    app_name.setStyleSheet(f"color: {FG}; background: transparent;")

    ver_badge = QLabel("v3")
    ver_badge.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
    ver_badge.setFixedSize(26, 16)
    ver_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
    ver_badge.setStyleSheet(f"""
        background: {ACCENT}; color: {BG};
        border-radius: 3px; padding: 0px;
    """)

    # status pill (top right)
    status_pill = QLabel("● Idle")
    status_pill.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
    status_pill.setStyleSheet(f"""
        color: {MUTED}; background: {CARD3};
        border-radius: 10px; padding: 3px 10px;
        border: 1px solid {BORDER};
    """)

    # IP chip
    ip_chip = QLabel(f"⌖  {local_ip}")
    ip_chip.setFont(QFont("Consolas", 9))
    ip_chip.setStyleSheet(f"""
        color: {FG2}; background: {CARD3};
        border-radius: 10px; padding: 3px 10px;
        border: 1px solid {BORDER};
    """)
    ip_chip.setToolTip("Your LAN IP address — share this with clients")

    tb_layout.addWidget(logo_lbl)
    tb_layout.addWidget(app_name)
    tb_layout.addWidget(ver_badge, 0, Qt.AlignmentFlag.AlignVCenter)
    tb_layout.addStretch()
    tb_layout.addWidget(ip_chip)
    tb_layout.addWidget(status_pill)
    win_layout.addWidget(title_bar)

    # ── tab bar ───────────────────────────────────────────────────────────────
    tab_bar_widget = QWidget()
    tab_bar_widget.setFixedHeight(38)
    tab_bar_widget.setStyleSheet(f"""
        QWidget {{
            background: {BG};
            border-bottom: 1px solid {BORDER};
        }}
    """)
    tab_bar_layout = QHBoxLayout(tab_bar_widget)
    tab_bar_layout.setContentsMargins(20, 0, 20, 0)
    tab_bar_layout.setSpacing(0)

    stack = QStackedWidget()
    _active_tab = [0]

    def _make_tab_btn(text, idx):
        btn = QPushButton(text)
        btn.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        btn.setFixedHeight(38)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setCheckable(True)

        def _style(active):
            if active:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: transparent;
                        color: {ACCENT};
                        border: none;
                        border-bottom: 2px solid {ACCENT};
                        border-radius: 0px;
                        padding: 0 18px;
                    }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: transparent;
                        color: {MUTED};
                        border: none;
                        border-bottom: 2px solid transparent;
                        border-radius: 0px;
                        padding: 0 18px;
                    }}
                    QPushButton:hover {{ color: {FG2}; }}
                """)
        btn._style = _style

        def _on_click():
            _active_tab[0] = idx
            stack.setCurrentIndex(idx)
            for b, i in _tab_btns:
                b._style(i == idx)
                b.setChecked(i == idx)
        btn.clicked.connect(_on_click)
        return btn

    _tab_btns = []
    for _i, _name in enumerate(["  ⌨  CONNECT", "  📋  CLIPBOARD", "  🖥  DISPLAYS"]):
        _b = _make_tab_btn(_name, _i)
        _b._style(_i == 0)
        _b.setChecked(_i == 0)
        tab_bar_layout.addWidget(_b)
        _tab_btns.append((_b, _i))
    tab_bar_layout.addStretch()

    win_layout.addWidget(tab_bar_widget)
    win_layout.addWidget(stack)

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 0: Connect tab
    # ══════════════════════════════════════════════════════════════════════════
    page_main = QWidget()
    page_main.setStyleSheet(f"background: {BG};")
    root_layout = QVBoxLayout(page_main)
    root_layout.setContentsMargins(20, 20, 20, 16)
    root_layout.setSpacing(0)
    stack.addWidget(page_main)

    # ── mode selector ─────────────────────────────────────────────────────────
    mode_label = lbl("SELECT ROLE", size=8, bold=True, color=MUTED)
    root_layout.addWidget(mode_label)
    root_layout.addSpacing(8)

    mode_row = QHBoxLayout()
    mode_row.setSpacing(10)
    _mode  = ["server"]
    _cards = {}

    def _card_qss(selected, accent_col):
        if selected:
            return f"""
                QFrame#modeCard {{
                    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                        stop:0 {CARD2}, stop:1 {CARD});
                    border: 1px solid {accent_col};
                    border-left: 3px solid {accent_col};
                    border-radius: 8px;
                }}
            """
        return f"""
            QFrame#modeCard {{
                background: {CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
            QFrame#modeCard:hover {{
                border: 1px solid {MUTED};
            }}
        """

    def make_mode_card(icon_ch, label, desc, value, col):
        frame = QFrame()
        frame.setObjectName("modeCard")
        frame.setCursor(Qt.CursorShape.PointingHandCursor)
        frame.setFixedHeight(100)

        inner = QVBoxLayout(frame)
        inner.setContentsMargins(16, 14, 16, 14)
        inner.setSpacing(5)

        # icon row
        icon_row = QHBoxLayout()
        icon_row.setSpacing(8)
        icon_w = QLabel(icon_ch)
        icon_w.setFont(QFont("Segoe UI Emoji", 18))
        icon_w.setStyleSheet(f"color: {col}; background: transparent; border: none;")

        title_w = QLabel(label)
        title_w.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        title_w.setStyleSheet(f"color: {FG}; background: transparent; border: none;")
        icon_row.addWidget(icon_w)
        icon_row.addWidget(title_w)
        icon_row.addStretch()

        desc_w = QLabel(desc)
        desc_w.setFont(QFont("Consolas", 9))
        desc_w.setWordWrap(True)
        desc_w.setStyleSheet(f"color: {FG2}; background: transparent; border: none;")

        inner.addLayout(icon_row)
        inner.addWidget(desc_w)

        frame.setStyleSheet(_card_qss(False, col))
        _cards[value] = (frame, col)

        def on_click(ev, v=value):
            _select_mode(v)
        frame.mousePressEvent = on_click
        return frame

    server_card = make_mode_card("🖥", "SERVER", "Controls mouse & keyboard — share your input", "server", ACCENT)
    client_card = make_mode_card("🖱", "CLIENT", "Receives input from the server machine", "client", ACCENT2)
    _apply_col   = lambda v, sel: _cards[v][0].setStyleSheet(_card_qss(sel, _cards[v][1]))

    _apply_col("server", True)

    def _select_mode(value):
        _mode[0] = value
        for v in _cards:
            _apply_col(v, v == value)
        ip_widget.setVisible(value == "client")
        if IS_WINDOWS:
            disable_kb_cb.setVisible(value == "client")

    mode_row.addWidget(server_card, 1)
    mode_row.addWidget(client_card, 1)
    root_layout.addLayout(mode_row)
    root_layout.addSpacing(14)

    # ── divider ───────────────────────────────────────────────────────────────
    root_layout.addWidget(hline())
    root_layout.addSpacing(14)

    # ── IP entry (client only) ────────────────────────────────────────────────
    ip_row = QHBoxLayout()
    ip_row.setSpacing(10)

    ip_label = lbl("SERVER IP", size=8, bold=True, color=MUTED)

    ip_entry = QLineEdit()
    ip_entry.setFont(QFont("Consolas", 13))
    ip_entry.setPlaceholderText("192.168.1.x")
    ip_entry.setText(_saved_ip)
    ip_entry.setFixedHeight(40)
    ip_entry.setStyleSheet(f"""
        QLineEdit {{
            background: {CARD};
            color: {FG};
            border: 1px solid {BORDER};
            border-radius: 6px;
            padding: 0 12px;
            selection-background-color: {ACCENT};
        }}
        QLineEdit:focus {{
            border: 1px solid {ACCENT};
            background: {CARD2};
        }}
    """)

    saved_lbl = lbl("", size=9, color=SUCCESS)

    ip_col = QVBoxLayout()
    ip_col.setSpacing(6)
    ip_col.addWidget(ip_label)
    ip_col.addWidget(ip_entry)

    ip_widget = QWidget()
    ip_widget.setStyleSheet("background: transparent;")
    ip_widget.setLayout(ip_col)
    ip_widget.hide()
    root_layout.addWidget(ip_widget)

    def _flash_saved():
        saved_lbl.setText("✓ saved")
        QTimer.singleShot(1500, lambda: saved_lbl.setText(""))

    def on_mode_change(btn):
        v = btn.property("modeValue")
        _mode[0] = v
        ip_widget.setVisible(v == "client")

    # ── options ───────────────────────────────────────────────────────────────
    opts_label = lbl("OPTIONS", size=8, bold=True, color=MUTED)
    root_layout.addWidget(opts_label)
    root_layout.addSpacing(8)

    opts_frame = QFrame()
    opts_frame.setStyleSheet(f"""
        QFrame {{
            background: {CARD};
            border: 1px solid {BORDER};
            border-radius: 8px;
        }}
    """)
    opts_layout = QVBoxLayout(opts_frame)
    opts_layout.setContentsMargins(16, 12, 16, 12)
    opts_layout.setSpacing(10)

    def make_check(text, tip=""):
        cb = QCheckBox(text)
        cb.setChecked(True)
        cb.setFont(QFont("Consolas", 10))
        cb.setToolTip(tip)
        cb.setStyleSheet(f"""
            QCheckBox {{ color: {FG}; spacing: 10px; background: transparent; }}
            QCheckBox::indicator {{
                width: 16px; height: 16px;
                border: 1px solid {BORDER};
                border-radius: 4px;
                background: {CARD2};
            }}
            QCheckBox::indicator:hover {{
                border: 1px solid {ACCENT};
            }}
            QCheckBox::indicator:checked {{
                background: {ACCENT};
                border: 1px solid {ACCENT};
                image: none;
            }}
        """)
        return cb

    edge_cb       = make_check("Edge-trigger hand-off",
                               "Drag cursor to screen edge to switch focus to client")
    clip_cb       = make_check("Clipboard sync",
                               "Automatically sync clipboard content between machines")
    auto_start_cb = make_check("Auto-start client on launch",
                               "Re-connect to saved server IP when ShareMouse starts")
    auto_start_cb.setChecked(_auto_start)

    # ── Disable Keyboard (client / Windows 11 only) ───────────────────────────
    _disable_kb_saved = _cfg.get("disable_keyboard", False)
    disable_kb_cb = make_check(
        "Disable keyboard  [client only]",
        "When active as a Windows 11 client, ignore all keyboard events "
        "received from the server — only mouse input is forwarded."
    )
    disable_kb_cb.setChecked(_disable_kb_saved)
    # Only relevant on Windows + client role; hide when server is selected
    disable_kb_cb.setVisible(IS_WINDOWS)   # always hidden on non-Windows

    def _on_disable_kb_toggled(state):
        save_config({"disable_keyboard": bool(state)})
        w = worker[0]
        if w is not None and _mode[0] == "client":
            if bool(state):
                w.disable_keyboard()
                log("⌨  Keyboard disabled — mouse-only client mode.")
            else:
                w.enable_keyboard()
                log("⌨  Keyboard re-enabled.")
    disable_kb_cb.stateChanged.connect(_on_disable_kb_toggled)

    # insert separators between checkboxes
    def _opt_row(cb):
        r = QHBoxLayout()
        r.setContentsMargins(0, 0, 0, 0)
        r.addWidget(cb)
        r.addStretch()
        return r

    opts_layout.addLayout(_opt_row(edge_cb))
    opts_layout.addWidget(hline())
    opts_layout.addLayout(_opt_row(clip_cb))
    opts_layout.addWidget(hline())
    opts_layout.addLayout(_opt_row(auto_start_cb))
    if IS_WINDOWS:
        opts_layout.addWidget(hline())
        opts_layout.addLayout(_opt_row(disable_kb_cb))

    def _on_auto_start_toggled(state):
        save_config({"auto_start": bool(state)})
    auto_start_cb.stateChanged.connect(_on_auto_start_toggled)

    root_layout.addWidget(opts_frame)
    root_layout.addSpacing(14)

    # ── log area ──────────────────────────────────────────────────────────────
    log_header = QHBoxLayout()
    log_title_lbl = lbl("ACTIVITY LOG", size=8, bold=True, color=MUTED)
    log_clear_btn = QPushButton("CLEAR")
    log_clear_btn.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
    log_clear_btn.setFixedSize(52, 20)
    log_clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    log_clear_btn.setStyleSheet(f"""
        QPushButton {{
            background: transparent;
            color: {MUTED};
            border: 1px solid {BORDER};
            border-radius: 3px;
        }}
        QPushButton:hover {{
            color: {FG};
            border-color: {MUTED};
        }}
    """)
    log_header.addWidget(log_title_lbl)
    log_header.addStretch()
    log_header.addWidget(log_clear_btn)
    root_layout.addLayout(log_header)
    root_layout.addSpacing(6)

    log_frame = QWidget()
    log_frame.setStyleSheet(f"""
        QWidget {{
            background: {CARD};
            border: 1px solid {BORDER};
            border-radius: 8px;
        }}
    """)
    log_inner = QVBoxLayout(log_frame)
    log_inner.setContentsMargins(12, 10, 12, 10)
    log_inner.setSpacing(0)

    log_box = QTextEdit()
    log_box.setReadOnly(True)
    log_box.setFont(QFont("Consolas", 9))
    log_box.setStyleSheet(f"""
        QTextEdit {{
            background: transparent;
            color: {ACCENT2};
            border: none;
            selection-background-color: {CARD3};
        }}
    """)
    log_box.setPlaceholderText("Events will appear here…")
    log_inner.addWidget(log_box)
    root_layout.addWidget(log_frame, 1)
    root_layout.addSpacing(14)

    log_clear_btn.clicked.connect(log_box.clear)

    def log(msg):
        ts = time.strftime("%H:%M:%S")
        # colour-code by keyword
        if any(k in msg for k in ("ERROR", "⚠", "CRASH")):
            color = DANGER
        elif any(k in msg for k in ("✓", "connected", "started", "Running")):
            color = SUCCESS
        elif any(k in msg for k in ("Paused", "⏸")):
            color = WARN
        else:
            color = ACCENT2
        log_box.append(
            f'<span style="color:{MUTED};">{ts}</span>'
            f'  <span style="color:{color};">{msg}</span>'
        )
        log_box.verticalScrollBar().setValue(log_box.verticalScrollBar().maximum())

    # ── bottom action bar ─────────────────────────────────────────────────────
    action_bar = QWidget()
    action_bar.setFixedHeight(64)
    action_bar.setStyleSheet(f"""
        QWidget {{
            background: {CARD};
            border-top: 1px solid {BORDER};
        }}
    """)
    ab_layout = QHBoxLayout(action_bar)
    ab_layout.setContentsMargins(20, 0, 20, 0)
    ab_layout.setSpacing(10)

    # status dot + label
    status_dot = lbl("●", size=14, color=MUTED)
    status_lbl = lbl("Idle", size=10, color=MUTED)

    def make_btn(text, bg, fg=BG, min_w=90):
        b = QPushButton(text)
        b.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setFixedHeight(38)
        b.setMinimumWidth(min_w)
        b.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {fg};
                border: none;
                border-radius: 6px;
                padding: 0 18px;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: {bg}DD;
            }}
            QPushButton:pressed {{
                background: {bg}AA;
            }}
        """)
        return b

    tray_btn  = make_btn("⊟  TRAY",   CARD3, FG2, min_w=80)
    tray_btn.setStyleSheet(tray_btn.styleSheet() + f"""
        QPushButton {{ border: 1px solid {BORDER}; }}
        QPushButton:hover {{ border-color: {MUTED}; color: {FG}; }}
    """)
    pause_btn = make_btn("⏸  PAUSE",  WARN,  BG,  min_w=90)
    start_btn = make_btn("▶  START",  ACCENT, BG, min_w=110)

    pause_btn.hide()

    ab_layout.addWidget(status_dot)
    ab_layout.addWidget(status_lbl)
    ab_layout.addStretch()
    ab_layout.addWidget(tray_btn)
    ab_layout.addWidget(pause_btn)
    ab_layout.addWidget(start_btn)

    root_layout.addWidget(action_bar)

    # ── status helpers ────────────────────────────────────────────────────────
    def set_status(running, note="", paused=False):
        if running:
            dot_color = WARN if paused else SUCCESS
            lbl_text  = f"{'Paused' if paused else 'Running'}{note}"
            status_dot.setStyleSheet(f"color:{dot_color}; background:transparent;")
            status_lbl.setStyleSheet(f"color:{dot_color}; background:transparent;")
            status_lbl.setText(lbl_text)
            status_pill.setText(f"● {lbl_text}")
            status_pill.setStyleSheet(f"""
                color: {dot_color}; background: {CARD3};
                border-radius: 10px; padding: 3px 10px;
                border: 1px solid {dot_color}44;
            """)
            start_btn.setText("■  STOP")
            start_btn.setStyleSheet(f"""
                QPushButton {{
                    background: {DANGER}; color: {BG};
                    border: none; border-radius: 6px;
                    padding: 0 18px; font-family: Consolas;
                    font-size: 10pt; font-weight: bold;
                }}
                QPushButton:hover {{ background: {DANGER}CC; }}
            """)
            if _mode[0] == "client":
                pause_btn.setText("▶  RESUME" if paused else "⏸  PAUSE")
                pause_btn.setStyleSheet(f"""
                    QPushButton {{
                        background: {"#23D18B" if paused else WARN};
                        color: {BG}; border: none; border-radius: 6px;
                        padding: 0 18px; font-family: Consolas;
                        font-size: 10pt; font-weight: bold;
                    }}
                """)
                pause_btn.show()
            else:
                pause_btn.hide()
        else:
            status_dot.setStyleSheet(f"color:{MUTED}; background:transparent;")
            status_lbl.setStyleSheet(f"color:{MUTED}; background:transparent;")
            status_lbl.setText("Idle")
            status_pill.setText("● Idle")
            status_pill.setStyleSheet(f"""
                color: {MUTED}; background: {CARD3};
                border-radius: 10px; padding: 3px 10px;
                border: 1px solid {BORDER};
            """)
            start_btn.setText("▶  START")
            start_btn.setStyleSheet(f"""
                QPushButton {{
                    background: {ACCENT}; color: {BG};
                    border: none; border-radius: 6px;
                    padding: 0 18px; font-family: Consolas;
                    font-size: 10pt; font-weight: bold;
                }}
                QPushButton:hover {{ background: {ACCENT}CC; }}
            """)
            pause_btn.hide()

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 1: Clipboard history tab
    # ══════════════════════════════════════════════════════════════════════════
    page_clip = QWidget()
    page_clip.setStyleSheet(f"background: {BG};")
    clip_page_layout = QVBoxLayout(page_clip)
    clip_page_layout.setContentsMargins(0, 0, 0, 0)
    clip_page_layout.setSpacing(0)
    stack.addWidget(page_clip)

    # ── clipboard imports ─────────────────────────────────────────────────────
    from PyQt6.QtWidgets import QScrollArea, QInputDialog, QSizePolicy
    from PyQt6.QtCore    import QTimer as _QTimer

    # ── in-memory list (mirrors the JSON file) ────────────────────────────────
    _clip_items   = _clip_history_load()   # list of dicts, newest first
    _clip_widgets = []                    # list of QFrame widgets in the scroll area
    _last_gui_clip = [_clip_get()]        # seed for GUI-side auto-capture watcher
    _auto_clip     = [True]              # auto-capture enabled by default

    # ── toolbar row ───────────────────────────────────────────────────────────
    clip_toolbar_widget = QWidget()
    clip_toolbar_widget.setFixedHeight(56)
    clip_toolbar_widget.setStyleSheet(f"background: {CARD}; border-bottom: 1px solid {BORDER};")
    clip_toolbar = QHBoxLayout(clip_toolbar_widget)
    clip_toolbar.setContentsMargins(16, 0, 16, 0)
    clip_toolbar.setSpacing(8)

    clip_search = QLineEdit()
    clip_search.setPlaceholderText("🔍  Search clips…")
    clip_search.setFont(QFont("Consolas", 10))
    clip_search.setFixedHeight(34)
    clip_search.setStyleSheet(f"""
        QLineEdit {{
            background: {CARD2};
            color: {FG};
            border: 1px solid {BORDER};
            border-radius: 6px;
            padding: 0 12px;
            selection-background-color: {ACCENT};
        }}
        QLineEdit:focus {{
            border: 1px solid {ACCENT};
        }}
    """)

    def _make_sm_btn(text, bg=CARD2, fg=FG, tip=""):
        b = QPushButton(text)
        b.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        b.setFixedHeight(34)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setToolTip(tip)
        b.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {fg};
                border: none;
                border-radius: 6px;
                padding: 0 14px;
            }}
            QPushButton:hover {{ background: {bg}BB; }}
        """)
        return b

    clip_auto_btn  = _make_sm_btn("⚡ AUTO",  ACCENT2, BG,  "Auto-save clipboard changes (click to pause)")
    clip_clear_btn = _make_sm_btn("⌫ CLEAR",  CARD3,  FG2, "Delete all unpinned items")
    clip_clear_btn.setStyleSheet(clip_clear_btn.styleSheet() +
        f"QPushButton {{ border: 1px solid {BORDER}; }}")

    clip_toolbar.addWidget(clip_auto_btn)
    clip_toolbar.addWidget(clip_search, 1)
    clip_toolbar.addWidget(clip_clear_btn)
    clip_page_layout.addWidget(clip_toolbar_widget)

    # ── scroll area ───────────────────────────────────────────────────────────
    clip_scroll = QScrollArea()
    clip_scroll.setWidgetResizable(True)
    clip_scroll.setStyleSheet(f"QScrollArea {{ background: {BG}; border: none; }}")

    clip_inner = QWidget()
    clip_inner.setStyleSheet(f"background: {BG};")
    clip_inner_layout = QVBoxLayout(clip_inner)
    clip_inner_layout.setContentsMargins(16, 12, 16, 16)
    clip_inner_layout.setSpacing(8)
    clip_inner_layout.addStretch()

    clip_scroll.setWidget(clip_inner)
    clip_page_layout.addWidget(clip_scroll, 1)

    # ── empty-state label ─────────────────────────────────────────────────────
    clip_empty_lbl = QLabel("No clips yet.\nCopy anything — it's saved automatically.")
    clip_empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    clip_empty_lbl.setFont(QFont("Consolas", 10))
    clip_empty_lbl.setStyleSheet(f"color: {MUTED}; background: transparent;")
    clip_inner_layout.insertWidget(0, clip_empty_lbl)

    # ── row builder ───────────────────────────────────────────────────────────
    def _rebuild_clip_list(filter_text=""):
        # Remove all existing row widgets
        for w in _clip_widgets:
            clip_inner_layout.removeWidget(w)
            w.deleteLater()
        _clip_widgets.clear()

        query = filter_text.strip().lower()
        visible = [i for i in _clip_items
                   if not query or query in i.get("content", "").lower()]

        clip_empty_lbl.setVisible(len(visible) == 0)

        # Insert rows before the trailing stretch (index len(_clip_widgets))
        for item in visible:
            _clip_widgets.append(_make_clip_row(item))
            idx = clip_inner_layout.count() - 1  # before stretch
            clip_inner_layout.insertWidget(idx, _clip_widgets[-1])

    def _make_clip_row(item: dict) -> "QFrame":
        content  = item.get("content", "")
        is_pin   = item.get("pinned",  False)
        is_rem   = item.get("remote",  False)
        item_id  = item.get("id",      "")

        # ── frame ─────────────────────────────────────────────────────────────
        frame = QFrame()
        frame.setFixedHeight(76)
        if is_pin:
            border_left = f"border-left: 3px solid {ACCENT};"
            bg_card = CARD2
        elif is_rem:
            border_left = f"border-left: 3px solid {ACCENT2};"
            bg_card = CARD
        else:
            border_left = ""
            bg_card = CARD

        frame.setStyleSheet(f"""
            QFrame {{
                background: {bg_card};
                border: 1px solid {BORDER};
                {border_left}
                border-radius: 8px;
            }}
        """)
        row = QHBoxLayout(frame)
        row.setContentsMargins(14, 8, 10, 8)
        row.setSpacing(10)

        # ── text block ────────────────────────────────────────────────────────
        txt_col = QVBoxLayout()
        txt_col.setSpacing(4)

        preview = content.replace("\n", " ↵ ")[:110]
        if len(content) > 110:
            preview += "…"

        preview_lbl = QLabel(preview)
        preview_lbl.setFont(QFont("Consolas", 9))
        preview_lbl.setStyleSheet(f"color: {FG}; background: transparent;")
        preview_lbl.setWordWrap(False)

        # meta chips row
        meta_parts = [f"{len(content)} chars"]
        if content.count("\n") > 0:
            meta_parts.append(f"{content.count(chr(10)) + 1} lines")
        if is_rem:
            meta_parts.append("⌨ synced")
        if is_pin:
            meta_parts.append("📌 pinned")
        meta_lbl = QLabel("  ·  ".join(meta_parts))
        meta_lbl.setFont(QFont("Consolas", 8))
        meta_lbl.setStyleSheet(f"color: {MUTED}; background: transparent;")

        txt_col.addWidget(preview_lbl)
        txt_col.addWidget(meta_lbl)
        row.addLayout(txt_col, 1)

        # ── action buttons ────────────────────────────────────────────────────
        def _icon_btn(icon, tip):
            b = QPushButton(icon)
            b.setFont(QFont("Segoe UI Emoji", 12))
            b.setFixedSize(32, 32)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setToolTip(tip)
            b.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {MUTED};
                    border: none;
                    border-radius: 6px;
                }}
                QPushButton:hover {{
                    background: {CARD3};
                    color: {FG};
                }}
            """)
            return b

        copy_btn = _icon_btn("⧉", "Copy to clipboard")
        pin_btn  = _icon_btn("📍" if is_pin else "📌", "Unpin" if is_pin else "Pin")
        del_btn  = _icon_btn("✕", "Delete")

        row.addWidget(copy_btn)
        row.addWidget(pin_btn)
        row.addWidget(del_btn)

        # ── button actions ────────────────────────────────────────────────────
        def _do_copy():
            _clip_set(content)
            copy_btn.setText("✓")
            copy_btn.setStyleSheet(copy_btn.styleSheet() + f"QPushButton {{ color: {SUCCESS}; }}")
            _QTimer.singleShot(1200, lambda: (
                copy_btn.setText("⧉"),
                copy_btn.setStyleSheet(copy_btn.styleSheet().replace(f"color: {SUCCESS};", "")),
            ))

        def _do_pin():
            for it in _clip_items:
                if it.get("id") == item_id:
                    it["pinned"] = not it.get("pinned", False)
                    break
            _clip_history_save(_clip_items)
            _rebuild_clip_list(clip_search.text())

        def _do_delete():
            idx = next((i for i, it in enumerate(_clip_items)
                        if it.get("id") == item_id), None)
            if idx is not None:
                _clip_items.pop(idx)
            _clip_history_save(_clip_items)
            _rebuild_clip_list(clip_search.text())

        copy_btn.clicked.connect(_do_copy)
        pin_btn .clicked.connect(_do_pin)
        del_btn .clicked.connect(_do_delete)

        return frame

    # ── toolbar actions ───────────────────────────────────────────────────────
    def _clip_add_current():
        """Save whatever is on the clipboard right now."""
        text = _clip_get()
        if not text or not text.strip():
            return
        _clip_items[:] = _clip_history_add(_clip_items, text, remote=False)
        _clip_history_save(_clip_items)
        _rebuild_clip_list(clip_search.text())

    def _clip_clear_unpinned():
        _clip_items[:] = [i for i in _clip_items if i.get("pinned")]
        _clip_history_save(_clip_items)
        _rebuild_clip_list(clip_search.text())

    def _toggle_auto_clip():
        _auto_clip[0] = not _auto_clip[0]
        if _auto_clip[0]:
            clip_auto_btn.setText("⚡ AUTO")
            clip_auto_btn.setStyleSheet(f"""
                QPushButton {{
                    background: {ACCENT2};
                    color: {BG};
                    border: none;
                    border-radius: 6px;
                    padding: 0 14px;
                }}
                QPushButton:hover {{ background: {ACCENT2}BB; }}
            """)
        else:
            clip_auto_btn.setText("⏸ PAUSED")
            clip_auto_btn.setStyleSheet(f"""
                QPushButton {{
                    background: {CARD3};
                    color: {MUTED};
                    border: 1px solid {BORDER};
                    border-radius: 6px;
                    padding: 0 14px;
                }}
                QPushButton:hover {{ background: {CARD2}; color: {FG2}; }}
            """)

    clip_auto_btn .clicked.connect(_toggle_auto_clip)
    clip_clear_btn.clicked.connect(_clip_clear_unpinned)
    clip_search.textChanged.connect(_rebuild_clip_list)

    def _ingest_clip_msg(text: str, remote: bool):
        """Called from poll_logs when a worker pushes a __clip__ message."""
        _last_gui_clip[0] = text          # keep GUI watcher in sync so it won't re-fire
        _clip_items[:] = _clip_history_add(_clip_items, text, remote=remote)
        _clip_history_save(_clip_items)
        if _active_tab[0] == 1:          # only rebuild if the tab is visible
            _rebuild_clip_list(clip_search.text())

    # ── GUI-side clipboard watcher (auto-capture, always on) ──────────────────
    # Runs every 1 s regardless of whether a worker is active.
    # Covers: idle, client mode, and the initial copy before START is pressed.
    def _auto_clip_tick():
        if not _auto_clip[0]:
            return
        cur = _clip_get()
        if cur and cur.strip() and cur != _last_gui_clip[0]:
            _last_gui_clip[0] = cur
            _ingest_clip_msg(cur, remote=False)

    clip_auto_timer = _QTimer()
    clip_auto_timer.timeout.connect(_auto_clip_tick)
    clip_auto_timer.start(1000)

    # Initial render
    _rebuild_clip_list()

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 2: Dual Display manager  (Windows 11 Client)
    # ══════════════════════════════════════════════════════════════════════════
    page_disp = QWidget()
    page_disp.setStyleSheet(f"background: {BG};")
    disp_page_layout = QVBoxLayout(page_disp)
    disp_page_layout.setContentsMargins(0, 0, 0, 0)
    disp_page_layout.setSpacing(0)
    stack.addWidget(page_disp)

    # ── toolbar ───────────────────────────────────────────────────────────────
    disp_toolbar_w = QWidget()
    disp_toolbar_w.setFixedHeight(56)
    disp_toolbar_w.setStyleSheet(f"background: {CARD}; border-bottom: 1px solid {BORDER};")
    disp_toolbar = QHBoxLayout(disp_toolbar_w)
    disp_toolbar.setContentsMargins(16, 0, 16, 0)
    disp_toolbar.setSpacing(10)

    disp_title_lbl = QLabel("DUAL DISPLAY MANAGER")
    disp_title_lbl.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
    disp_title_lbl.setStyleSheet(f"color: {ACCENT}; background: transparent;")

    disp_os_badge = QLabel("Windows 11" if IS_WINDOWS else "Windows only")
    disp_os_badge.setFont(QFont("Consolas", 8))
    disp_os_badge.setStyleSheet(f"""
        color: {BG}; background: {"#0078D4" if IS_WINDOWS else MUTED};
        border-radius: 4px; padding: 2px 8px;
    """)

    def _make_disp_sm_btn(text, bg=CARD2, fg=FG, tip=""):
        b = QPushButton(text)
        b.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        b.setFixedHeight(34)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setToolTip(tip)
        b.setStyleSheet(f"""
            QPushButton {{
                background: {bg}; color: {fg};
                border: none; border-radius: 6px; padding: 0 14px;
            }}
            QPushButton:hover {{ background: {bg}BB; }}
            QPushButton:disabled {{ background: {CARD3}; color: {MUTED}; }}
        """)
        return b

    disp_refresh_btn = _make_disp_sm_btn("⟳  REFRESH", ACCENT2, BG,
                                         "Re-scan monitors connected to this Windows 11 client")
    disp_toolbar.addWidget(disp_title_lbl)
    disp_toolbar.addWidget(disp_os_badge, 0, Qt.AlignmentFlag.AlignVCenter)
    disp_toolbar.addStretch()
    disp_toolbar.addWidget(disp_refresh_btn)
    disp_page_layout.addWidget(disp_toolbar_w)

    # ── scroll area ───────────────────────────────────────────────────────────
    disp_scroll = QScrollArea()
    disp_scroll.setWidgetResizable(True)
    disp_scroll.setStyleSheet(f"QScrollArea {{ background: {BG}; border: none; }}")

    disp_inner = QWidget()
    disp_inner.setStyleSheet(f"background: {BG};")
    disp_inner_layout = QVBoxLayout(disp_inner)
    disp_inner_layout.setContentsMargins(16, 16, 16, 16)
    disp_inner_layout.setSpacing(12)

    disp_scroll.setWidget(disp_inner)
    disp_page_layout.addWidget(disp_scroll, 1)

    # ── state ─────────────────────────────────────────────────────────────────
    _disp_monitors   = []    # list of monitor dicts from _win_get_monitors()
    _disp_active_idx = [-1]  # index of the currently selected target monitor
    _disp_cards      = []    # list of QFrame widgets, one per monitor

    # ── visual monitor map ────────────────────────────────────────────────────
    _disp_map_frame = QFrame()
    _disp_map_frame.setFixedHeight(140)
    _disp_map_frame.setStyleSheet(f"""
        QFrame {{
            background: {CARD};
            border: 1px solid {BORDER};
            border-radius: 10px;
        }}
    """)
    _disp_map_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    disp_inner_layout.addWidget(_disp_map_frame)

    def _repaint_monitor_map():
        """Draw a proportional bird's-eye view of all monitors on _disp_map_frame."""
        from PyQt6.QtGui import QFontMetrics

        # Clear old child widgets
        for ch in _disp_map_frame.findChildren(QLabel):
            ch.deleteLater()
        for ch in _disp_map_frame.findChildren(QFrame):
            if ch is not _disp_map_frame:
                ch.deleteLater()

        mons = _disp_monitors
        if not mons:
            no_lbl = QLabel("No monitors detected.", _disp_map_frame)
            no_lbl.setFont(QFont("Consolas", 10))
            no_lbl.setStyleSheet(f"color: {MUTED}; background: transparent;")
            no_lbl.move(16, 55)
            no_lbl.show()
            return

        # Virtual desktop bounding box
        vx0 = min(m["x"] for m in mons)
        vy0 = min(m["y"] for m in mons)
        vx1 = max(m["x"] + m["w"] for m in mons)
        vy1 = max(m["y"] + m["h"] for m in mons)
        vw  = vx1 - vx0 or 1
        vh  = vy1 - vy0 or 1

        PAD = 14
        avail_w = _disp_map_frame.width()  - PAD * 2
        avail_h = _disp_map_frame.height() - PAD * 2
        scale   = min(avail_w / vw, avail_h / vh)

        for m in mons:
            active = (m["index"] == _disp_active_idx[0])
            rx = PAD + int((m["x"] - vx0) * scale)
            ry = PAD + int((m["y"] - vy0) * scale)
            rw = max(30, int(m["w"] * scale))
            rh = max(22, int(m["h"] * scale))

            mon_box = QFrame(_disp_map_frame)
            mon_box.setGeometry(rx, ry, rw, rh)
            if active:
                mon_box.setStyleSheet(f"""
                    QFrame {{
                        background: {ACCENT}22;
                        border: 2px solid {ACCENT};
                        border-radius: 4px;
                    }}
                """)
            else:
                mon_box.setStyleSheet(f"""
                    QFrame {{
                        background: {CARD2};
                        border: 1px solid {BORDER};
                        border-radius: 4px;
                    }}
                """)

            map_lbl = QLabel(m["label"].split(" ★")[0], mon_box)
            map_lbl.setFont(QFont("Consolas", 7, QFont.Weight.Bold))
            map_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            map_lbl.setStyleSheet(
                f"color: {ACCENT if active else MUTED}; background: transparent;"
            )
            map_lbl.setGeometry(0, 0, rw, rh)
            mon_box.show()

        _disp_map_frame.update()

    _disp_map_frame.resizeEvent = lambda e: _repaint_monitor_map()

    # ── section label ─────────────────────────────────────────────────────────
    disp_monitors_label = QLabel("SELECT TARGET DISPLAY")
    disp_monitors_label.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
    disp_monitors_label.setStyleSheet(f"color: {MUTED}; background: transparent;")
    disp_inner_layout.addWidget(disp_monitors_label)

    _disp_cards_container = QWidget()
    _disp_cards_container.setStyleSheet("background: transparent;")
    _disp_cards_layout = QVBoxLayout(_disp_cards_container)
    _disp_cards_layout.setContentsMargins(0, 0, 0, 0)
    _disp_cards_layout.setSpacing(8)
    disp_inner_layout.addWidget(_disp_cards_container)

    # ── cursor warp controls ──────────────────────────────────────────────────
    warp_section_label = QLabel("CURSOR WARP TO DISPLAY")
    warp_section_label.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
    warp_section_label.setStyleSheet(f"color: {MUTED}; background: transparent;")
    disp_inner_layout.addWidget(warp_section_label)

    warp_frame = QFrame()
    warp_frame.setStyleSheet(f"""
        QFrame {{
            background: {CARD};
            border: 1px solid {BORDER};
            border-radius: 8px;
        }}
    """)
    warp_inner = QVBoxLayout(warp_frame)
    warp_inner.setContentsMargins(14, 12, 14, 12)
    warp_inner.setSpacing(10)

    warp_desc = QLabel(
        "Instantly warp your physical cursor to a specific position on the selected\n"
        "target display.  Useful after switching focus with the server."
    )
    warp_desc.setFont(QFont("Consolas", 9))
    warp_desc.setStyleSheet(f"color: {FG2}; background: transparent;")
    warp_inner.addWidget(warp_desc)

    warp_row = QHBoxLayout()
    warp_row.setSpacing(8)

    _warp_btns = {}
    for _edge, _icon, _tip in [
        ("left",   "◀  LEFT",   "Warp cursor to left edge of selected display"),
        ("center", "⊕  CENTER", "Warp cursor to center of selected display"),
        ("right",  "▶  RIGHT",  "Warp cursor to right edge of selected display"),
        ("top",    "▲  TOP",    "Warp cursor to top edge of selected display"),
        ("bottom", "▼  BOTTOM", "Warp cursor to bottom edge of selected display"),
    ]:
        _wb = _make_disp_sm_btn(_icon, CARD2, FG2, _tip)
        _wb.setStyleSheet(_wb.styleSheet() + f"QPushButton {{ border: 1px solid {BORDER}; }}")
        warp_row.addWidget(_wb)
        _warp_btns[_edge] = _wb

    def _do_warp(edge):
        if not IS_WINDOWS:
            return
        idx = _disp_active_idx[0]
        if idx < 0 or idx >= len(_disp_monitors):
            log("⚠  Select a target display first (DISPLAYS tab).")
            return
        _win_warp_to_monitor(_disp_monitors[idx], edge)
        log(f"Cursor warped → {_disp_monitors[idx]['label']} ({edge})")

    for _edge_key, _wb in _warp_btns.items():
        _wb.clicked.connect(lambda _chk=False, e=_edge_key: _do_warp(e))

    warp_inner.addLayout(warp_row)
    disp_inner_layout.addWidget(warp_frame)

    # ── coordinate mode section ───────────────────────────────────────────────
    coord_section_label = QLabel("COORDINATE MAPPING")
    coord_section_label.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
    coord_section_label.setStyleSheet(f"color: {MUTED}; background: transparent;")
    disp_inner_layout.addWidget(coord_section_label)

    coord_frame = QFrame()
    coord_frame.setStyleSheet(f"""
        QFrame {{
            background: {CARD};
            border: 1px solid {BORDER};
            border-radius: 8px;
        }}
    """)
    coord_inner = QVBoxLayout(coord_frame)
    coord_inner.setContentsMargins(14, 12, 14, 12)
    coord_inner.setSpacing(10)

    def _make_coord_check(text, tip=""):
        cb = QCheckBox(text)
        cb.setFont(QFont("Consolas", 10))
        cb.setToolTip(tip)
        cb.setStyleSheet(f"""
            QCheckBox {{ color: {FG}; spacing: 10px; background: transparent; }}
            QCheckBox::indicator {{
                width: 16px; height: 16px;
                border: 1px solid {BORDER};
                border-radius: 4px; background: {CARD2};
            }}
            QCheckBox::indicator:hover {{ border: 1px solid {ACCENT}; }}
            QCheckBox::indicator:checked {{
                background: {ACCENT}; border: 1px solid {ACCENT};
            }}
        """)
        return cb

    span_all_cb = _make_coord_check(
        "Span full virtual desktop  (multi-monitor seamless)",
        "Map server coordinates across the entire virtual desktop (all monitors combined). "
        "Use this when the server has a matching multi-monitor layout."
    )
    per_mon_cb = _make_coord_check(
        "Restrict to selected display  (single-monitor target)",
        "Clamp all incoming mouse coordinates to the selected display only. "
        "Best when the server is single-monitor."
    )
    span_all_cb.setChecked(False)
    per_mon_cb.setChecked(True)

    # saved preferences
    _coord_saved = load_config()
    if _coord_saved.get("disp_span_all"):
        span_all_cb.setChecked(True)
        per_mon_cb.setChecked(False)

    def _apply_coord_mode():
        if not IS_WINDOWS:
            return
        idx = _disp_active_idx[0]
        if span_all_cb.isChecked():
            # Reset offset so coordinates map across full virtual desktop
            _win_reset_to_span()
            vdw = _user32.GetSystemMetrics(78)
            vdh = _user32.GetSystemMetrics(79)
            log(f"Coord mode: SPAN all displays  (virtual desktop {vdw}×{vdh})")
        else:
            if idx < 0 or idx >= len(_disp_monitors):
                return
            mon = _disp_monitors[idx]
            _win_set_monitor_as_client_target(mon)
            log(f"Coord mode: TARGET {mon['label']}  "
                f"offset ({mon['x']}, {mon['y']})  "
                f"size {mon['w']}×{mon['h']}")

    def _on_span_toggle(state):
        if state:
            per_mon_cb.setChecked(False)
        save_config({"disp_span_all": bool(state)})
        _apply_coord_mode()

    def _on_per_mon_toggle(state):
        if state:
            span_all_cb.setChecked(False)
        save_config({"disp_span_all": not bool(state)})
        _apply_coord_mode()

    span_all_cb.stateChanged.connect(_on_span_toggle)
    per_mon_cb.stateChanged.connect(_on_per_mon_toggle)

    def _hline_disp():
        ln = QFrame()
        ln.setFrameShape(QFrame.Shape.HLine)
        ln.setStyleSheet(f"color: {BORDER}; background: {BORDER};")
        ln.setFixedHeight(1)
        return ln

    coord_inner.addWidget(span_all_cb)
    coord_inner.addWidget(_hline_disp())
    coord_inner.addWidget(per_mon_cb)
    disp_inner_layout.addWidget(coord_frame)

    # ── hotkey info panel ─────────────────────────────────────────────────────
    hk_frame = QFrame()
    hk_frame.setStyleSheet(f"""
        QFrame {{
            background: {CARD2};
            border: 1px solid {BORDER};
            border-left: 3px solid {ACCENT3};
            border-radius: 8px;
        }}
    """)
    hk_inner = QVBoxLayout(hk_frame)
    hk_inner.setContentsMargins(14, 10, 14, 10)
    hk_inner.setSpacing(6)

    hk_title = QLabel("KEYBOARD SHORTCUTS")
    hk_title.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
    hk_title.setStyleSheet(f"color: {ACCENT3}; background: transparent;")
    hk_inner.addWidget(hk_title)

    for _hk_line in [
        ("Ctrl + Alt + K",   "Toggle mouse lock (pin cursor, send relative moves)"),
        ("Win + P",          "Windows 11 — cycle display projection mode"),
        ("Win + Ctrl + ←/→", "Move focused window to adjacent display"),
        ("Win + Shift + ←/→","Snap window to adjacent display"),
    ]:
        row_w = QHBoxLayout()
        row_w.setSpacing(16)
        k_lbl = QLabel(_hk_line[0])
        k_lbl.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        k_lbl.setStyleSheet(f"""
            color: {BG}; background: {ACCENT};
            border-radius: 3px; padding: 1px 6px;
        """)
        k_lbl.setFixedWidth(180)
        d_lbl = QLabel(_hk_line[1])
        d_lbl.setFont(QFont("Consolas", 9))
        d_lbl.setStyleSheet(f"color: {FG2}; background: transparent;")
        row_w.addWidget(k_lbl)
        row_w.addWidget(d_lbl)
        row_w.addStretch()
        hk_inner.addLayout(row_w)

    disp_inner_layout.addWidget(hk_frame)
    disp_inner_layout.addStretch()

    # ── monitor card builder ──────────────────────────────────────────────────
    def _build_monitor_cards():
        """Rebuild the per-monitor selection cards list."""
        for old in _disp_cards:
            _disp_cards_layout.removeWidget(old)
            old.deleteLater()
        _disp_cards.clear()

        if not _disp_monitors:
            no_m = QLabel("No displays found — run as Windows 11 client and click REFRESH.")
            no_m.setFont(QFont("Consolas", 10))
            no_m.setStyleSheet(f"color: {MUTED}; background: transparent;")
            no_m.setAlignment(Qt.AlignmentFlag.AlignCenter)
            _disp_cards_layout.addWidget(no_m)
            return

        def _card_border_style(active):
            if active:
                return f"""
                    QFrame#dispCard {{
                        background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                            stop:0 {CARD2}, stop:1 {CARD});
                        border: 1px solid {ACCENT};
                        border-left: 3px solid {ACCENT};
                        border-radius: 8px;
                    }}
                """
            return f"""
                QFrame#dispCard {{
                    background: {CARD};
                    border: 1px solid {BORDER};
                    border-radius: 8px;
                }}
                QFrame#dispCard:hover {{ border: 1px solid {MUTED}; }}
            """

        for mon in _disp_monitors:
            card = QFrame()
            card.setObjectName("dispCard")
            card.setFixedHeight(86)
            card.setCursor(Qt.CursorShape.PointingHandCursor)
            is_active = (mon["index"] == _disp_active_idx[0])
            card.setStyleSheet(_card_border_style(is_active))

            c_lay = QHBoxLayout(card)
            c_lay.setContentsMargins(14, 10, 14, 10)
            c_lay.setSpacing(14)

            # ── monitor icon ──────────────────────────────────────────────────
            icon_lbl = QLabel("🖥")
            icon_lbl.setFont(QFont("Segoe UI Emoji", 22))
            icon_lbl.setStyleSheet(f"color: {ACCENT if is_active else MUTED}; background: transparent; border: none;")
            icon_lbl.setFixedWidth(36)
            c_lay.addWidget(icon_lbl)

            # ── info block ────────────────────────────────────────────────────
            info_col = QVBoxLayout()
            info_col.setSpacing(4)

            name_row = QHBoxLayout()
            name_row.setSpacing(8)

            name_lbl = QLabel(mon["label"])
            name_lbl.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            name_lbl.setStyleSheet(f"color: {FG if is_active else FG2}; background: transparent; border: none;")
            name_row.addWidget(name_lbl)

            if mon.get("primary"):
                pri_badge = QLabel("PRIMARY")
                pri_badge.setFont(QFont("Consolas", 7, QFont.Weight.Bold))
                pri_badge.setStyleSheet(f"""
                    color: {BG}; background: {ACCENT2};
                    border-radius: 3px; padding: 1px 5px; border: none;
                """)
                name_row.addWidget(pri_badge)

            if is_active:
                act_badge = QLabel("● TARGET")
                act_badge.setFont(QFont("Consolas", 7, QFont.Weight.Bold))
                act_badge.setStyleSheet(f"""
                    color: {ACCENT}; background: {ACCENT}22;
                    border-radius: 3px; padding: 1px 5px; border: 1px solid {ACCENT}66;
                """)
                name_row.addWidget(act_badge)

            name_row.addStretch()
            info_col.addLayout(name_row)

            res_text = (
                f"{mon['w']}×{mon['h']}  •  "
                f"offset ({mon['x']}, {mon['y']})  •  "
                f"work area {mon['work_w']}×{mon['work_h']}  •  "
                f"{mon.get('device','')}"
            )
            res_lbl = QLabel(res_text)
            res_lbl.setFont(QFont("Consolas", 8))
            res_lbl.setStyleSheet(f"color: {MUTED}; background: transparent; border: none;")
            res_lbl.setWordWrap(True)
            info_col.addWidget(res_lbl)

            c_lay.addLayout(info_col, 1)

            # ── select button ─────────────────────────────────────────────────
            sel_btn = QPushButton("✓ ACTIVE" if is_active else "SELECT")
            sel_btn.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
            sel_btn.setFixedSize(80, 30)
            sel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if is_active:
                sel_btn.setStyleSheet(f"""
                    QPushButton {{
                        background: {ACCENT}; color: {BG};
                        border: none; border-radius: 5px;
                    }}
                """)
            else:
                sel_btn.setStyleSheet(f"""
                    QPushButton {{
                        background: {CARD3}; color: {FG2};
                        border: 1px solid {BORDER}; border-radius: 5px;
                    }}
                    QPushButton:hover {{ border-color: {ACCENT}; color: {FG}; }}
                """)
            c_lay.addWidget(sel_btn)

            def _on_select(checked=False, idx=mon["index"]):
                _disp_active_idx[0] = idx
                _build_monitor_cards()
                _repaint_monitor_map()
                _apply_coord_mode()
                log(f"🖥  Target display → {_disp_monitors[idx]['label']}  "
                    f"({_disp_monitors[idx]['w']}×{_disp_monitors[idx]['h']} "
                    f"@ {_disp_monitors[idx]['x']},{_disp_monitors[idx]['y']})")

            sel_btn.clicked.connect(_on_select)
            card.mousePressEvent = lambda ev, i=mon["index"]: _on_select(idx=i)

            _disp_cards.append(card)
            _disp_cards_layout.addWidget(card)

        _repaint_monitor_map()

    # ── refresh ───────────────────────────────────────────────────────────────
    def _disp_refresh():
        if IS_WINDOWS:
            _disp_monitors.clear()
            _disp_monitors.extend(_win_get_monitors())
            # Auto-select primary monitor if nothing selected
            if _disp_active_idx[0] < 0:
                for m in _disp_monitors:
                    if m.get("primary"):
                        _disp_active_idx[0] = m["index"]
                        break
                if _disp_active_idx[0] < 0 and _disp_monitors:
                    _disp_active_idx[0] = 0
            _build_monitor_cards()
            _apply_coord_mode()
            n = len(_disp_monitors)
            log(f"🖥  {n} display{'s' if n != 1 else ''} detected.")
        else:
            log("⚠  Display management requires Windows 11 client mode.")
            _build_monitor_cards()

    disp_refresh_btn.clicked.connect(_disp_refresh)

    # Auto-refresh when the DISPLAYS tab becomes active
    def _on_tab_changed_disp(idx):
        if idx == 2 and not _disp_monitors:
            _disp_refresh()

    # Hook tab buttons to detect DISPLAYS tab activation
    for _tb, _ti in _tab_btns:
        if _ti == 2:
            _orig_click = _tb.clicked
            _tb.clicked.connect(lambda _chk=False: _on_tab_changed_disp(2))
            break

    # ── toggle pause ──────────────────────────────────────────────────────────
    def toggle_pause():
        w = worker[0]
        if w is None:
            return
        if w.paused:
            w.resume()
            log("▶  Resumed – input forwarding active.")
            set_status(True, f"  [{_mode[0]}]", paused=False)
        else:
            w.pause()
            log("⏸  Paused – connection kept alive, input suspended.")
            set_status(True, f"  [{_mode[0]}]", paused=True)

    pause_btn.clicked.connect(toggle_pause)

    # ── toggle start/stop ─────────────────────────────────────────────────────
    def toggle():
        if worker[0] is not None:
            worker[0].stop()
            worker[0] = None
            set_status(False)
            log("Stopped.")
            return

        if _mode[0] == "server":
            w = WorkerProcess(_server_worker)
            w.start()
            worker[0] = w
            set_status(True, "  [server]")
            log(f"Server started. Tell clients to connect to {local_ip}")
            if IS_WINDOWS and edge_cb.isChecked():
                log("Edge-trigger enabled: drag cursor to screen edge to switch focus.")
        else:
            ip = ip_entry.text().strip()
            if not ip or ip == "192.168.1.x":
                log("⚠  Enter the server IP first.")
                return
            save_config({"client_ip": ip})
            _flash_saved()
            w = WorkerProcess(_client_worker, args=(ip,))
            w.start()
            worker[0] = w
            # Apply saved keyboard-disable preference immediately on start
            if IS_WINDOWS and disable_kb_cb.isChecked():
                w.disable_keyboard()
                log("⌨  Keyboard disabled — mouse-only client mode active.")
            set_status(True, "  [client]")
            log(f"Client connecting to {ip} …")

    start_btn.clicked.connect(toggle)

    # ── system tray ───────────────────────────────────────────────────────────
    tray = QSystemTrayIcon(QIcon(_make_tray_pixmap()), app)
    tray.setToolTip("ShareMouse v3")

    tray_menu = QMenu()
    tray_menu.setStyleSheet(f"""
        QMenu {{
            background: {CARD2};
            color: {FG};
            border: 1px solid {CARD2};
        }}
        QMenu::item:selected {{ background: {ACCENT}; color: {BG}; }}
    """)

    act_show   = tray_menu.addAction("Show window")
    act_toggle = tray_menu.addAction("Toggle Start/Stop")
    tray_menu.addSeparator()
    act_quit   = tray_menu.addAction("Quit")

    tray.setContextMenu(tray_menu)
    tray.show()

    def tray_show():
        win.showNormal()
        win.activateWindow()

    def tray_toggle():
        w = worker[0]
        if w and w.running:
            w.stop()
            worker[0] = None
            log("Stopped (tray).")
            set_status(False)
        else:
            if _mode[0] == "server":
                nw = WorkerProcess(_server_worker)
                nw.start()
                worker[0] = nw
                log(f"Server started. Clients → {local_ip}")
                set_status(True, "  [server]")
            else:
                ip = ip_entry.text().strip()
                if ip:
                    nw = WorkerProcess(_client_worker, args=(ip,))
                    nw.start()
                    if IS_WINDOWS and disable_kb_cb.isChecked():
                        nw.disable_keyboard()
                    worker[0] = nw
                    log(f"Client connecting to {ip}")
                    set_status(True, "  [client]")

    def tray_quit():
        if worker[0]:
            worker[0].stop()
        tray.hide()
        app.quit()

    act_show.triggered.connect(tray_show)
    act_toggle.triggered.connect(tray_toggle)
    act_quit.triggered.connect(tray_quit)
    tray.activated.connect(lambda reason:
        tray_show() if reason == QSystemTrayIcon.ActivationReason.DoubleClick
        else None)

    def hide_to_tray():
        win.hide()
        tray.showMessage("ShareMouse", "Running in tray. Double-click to restore.",
                         QSystemTrayIcon.MessageIcon.Information, 2000)

    tray_btn.clicked.connect(hide_to_tray)

    # ── poll worker logs (250 ms timer) ───────────────────────────────────────
    poll_timer = QTimer()

    def poll_logs():
        if worker[0]:
            for msg in worker[0].drain_logs():
                if isinstance(msg, dict) and "__clip__" in msg:
                    # Worker detected a clipboard change — ingest it into history
                    _ingest_clip_msg(msg["__clip__"], msg.get("__remote__", False))
                else:
                    log(msg)
            if worker[0] and not worker[0].running:
                worker[0] = None
                set_status(False)
                log("⚠  Worker process exited unexpectedly.")

    poll_timer.timeout.connect(poll_logs)
    poll_timer.start(250)

    # ── clean exit ────────────────────────────────────────────────────────────
    def on_close():
        poll_timer.stop()
        clip_auto_timer.stop()
        if worker[0]:
            worker[0].stop()
        tray.hide()
        app.quit()

    app.aboutToQuit.connect(on_close)
    win.closeEvent = lambda e: (on_close(), e.accept())

    # ── initial log messages ──────────────────────────────────────────────────
    log(f"✓ Ready — your LAN IP: {local_ip}")
    if _saved_ip:
        log(f"✓ Loaded saved server IP: {_saved_ip}")
    if IS_WINDOWS:
        log("✓ Windows native input (ctypes SendInput).")
    else:
        log("macOS: grant Accessibility → Terminal in System Settings.")

    win.show()

    # ── auto-start (client mode, saved IP, checkbox ticked) ───────────────────
    if _auto_start and _saved_ip and _saved_ip != "192.168.1.x":
        _select_mode("client")          # switch UI to client card
        log(f"⚡  Auto-starting client → {_saved_ip}")
        QTimer.singleShot(300, toggle)  # slight delay so the window renders first

    app.exec()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    multiprocessing.freeze_support()   # ← must be first inside __main__ for PyInstaller

    # ── dependency pre-check ──────────────────────────────────────────────────
    _missing = []
    for _pkg, _imp in [("PyQt6",     "PyQt6.QtWidgets"),
                       ("pynput",    "pynput"),
                       ("pyperclip", "pyperclip")]:
        try:
            __import__(_imp)
        except ImportError:
            _missing.append(_pkg)

    if _missing:
        print("=" * 60)
        print("ERROR: Missing required packages:")
        for m in _missing:
            print(f"   pip install {m}")
        print("=" * 60)
        input("Press Enter to exit…")
        sys.exit(1)

    # ── launch ────────────────────────────────────────────────────────────────
    try:
        if len(sys.argv) == 1:
            launch_gui()
        elif sys.argv[1] == "server":
            run_server_headless()
        elif sys.argv[1] == "client" and len(sys.argv) >= 3:
            run_client_headless(sys.argv[2])
        else:
            print(__doc__)
    except Exception as _e:
        import traceback
        print("\n" + "=" * 60)
        print("CRASH REPORT — please share this with the developer:")
        print("=" * 60)
        traceback.print_exc()
        print("=" * 60)
        input("\nPress Enter to exit…")