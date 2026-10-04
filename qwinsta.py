#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse
import logging

from impacket.examples import logger as impacket_logger  # noqa: F401  (sets up logging style)
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import tsts
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import smb3, smbconnection


# --------------------------------------------------------------------------- #
# State and type mapping (matches UTILDLL!StrConnectState used by qwinsta.exe) #
# --------------------------------------------------------------------------- #

# WTS_CONNECTSTATE_CLASS value -> short label printed by qwinsta.
# These short strings are exactly what the native UTILDLL!StrConnectState returns.
STATE_SHORT = {
    0: "Active",   # State_Active        user logged on, client connected
    1: "Conn",     # State_Connected     client connected, no logon yet
    2: "ConnQ",    # State_ConnectQuery  connecting
    3: "Shadow",   # State_Shadow        shadowing another session
    4: "Disc",     # State_Disconnected  logged on, client disconnected
    5: "Idle",     # State_Idle          listener/station waiting
    6: "Listen",   # State_Listen        listener waiting for connections
    7: "Reset",    # State_Reset         being reset
    8: "Down",     # State_Down          down / error
    9: "Init",     # State_Init          initialising
}

# SESSIONTYPE GUID/enum -> label (used only with --type / verbose output).
SESSION_TYPE = {
    0: "",            # unknown
    1: "services",
    2: "listener",
    3: "desktop",
    4: "altshell",
    5: "remoteapp",
    6: "mediacenter",
}


class Session(object):
    """One remote Terminal Services session row."""

    __slots__ = ("id", "name", "state", "user", "domain", "sess_type", "is_current")

    def __init__(self, sid, name, state):
        self.id = sid
        self.name = name or ""
        self.state = state
        self.user = ""
        self.domain = ""
        self.sess_type = None
        self.is_current = False

    @property
    def state_label(self):
        return STATE_SHORT.get(int(self.state), str(int(self.state)))

    @property
    def user_label(self):
        # qwinsta prints the bare user name (no domain) in the USERNAME column.
        return self.user or ""

    @property
    def type_label(self):
        if self.sess_type is None:
            return ""
        return SESSION_TYPE.get(int(self.sess_type), "")


# --------------------------------------------------------------------------- #
# RPC plumbing                                                                 #
# --------------------------------------------------------------------------- #

def _iter_enum_result(resp):
    """Yield (SessionId, State, Name) from an RpcGetEnumResultEx(Level=1) response.

    The response carries a PSESSIONENUM pointer to a conformant array of
    SessionInfo_STRUCT unions.  We defensively support the couple of ways
    impacket surfaces the referent across versions.
    """
    container = resp["ppSessionEnumResult"]
    # NDRPOINTER -> referent field 'Data' is the conformant array; some versions
    # let you iterate the pointer directly.
    try:
        array = container["Data"]
    except (KeyError, TypeError):
        array = container

    for element in array:
        info = element["SessionInfo"]
        level1 = info["SessionEnum_Level1"]
        name = level1["Name"]
        if isinstance(name, bytes):
            name = name.decode("utf-16-le", "replace")
        name = name.split("\x00", 1)[0].rstrip("\x00")
        yield int(level1["SessionId"]), int(level1["State"]), name


def enumerate_sessions(smb, target_ip, do_kerberos):
    """Enumerate sessions via the TermSrvEnumeration interface (WinStationEnumerateW)."""
    sessions = []
    with tsts.TermSrvEnumeration(smb, target_ip, do_kerberos) as te:
        handle = te.hRpcOpenEnum()
        try:
            resp = te.hRpcGetEnumResultEx(handle, Level=1)
        finally:
            te.hRpcCloseEnum(handle)
        for sid, state, name in _iter_enum_result(resp):
            sessions.append(Session(sid, name, state))
    return sessions


def _deref(pointer):
    """Return an NDR pointer's referent ('Data'), or None for a NULL pointer."""
    try:
        return pointer["Data"]
    except (KeyError, TypeError):
        return None


def _clean_wstr(value):
    """Turn whatever an NDR wide-string field yields into a trimmed Python str.

    Fixed WCHAR[] arrays already decode to str; LPWCHAR_STRIPPED fields are NDR
    pointers to a WIDESTR referent and must be dereferenced first.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-16-le", "replace")
    if not isinstance(value, str):
        # NDR pointer / struct: follow the referent, else fall back to str().
        inner = _deref(value)
        value = inner if inner is not None else value
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception:  # noqa: BLE001
                return ""
    return value.split("\x00", 1)[0].rstrip("\x00")


def enrich_sessions(smb, target_ip, do_kerberos, sessions, want_type=False,
                    debug=False):
    """Fill in user name / domain (and the live SessionName, State and type).

    Primary source is RpcGetSessionInformationEx (one call per session id,
    returns UserName / DomainName / SessionName / SessionState directly, with no
    per-session handle). This mirrors WinStationQueryInformationW. We fall back
    to RpcOpenSession + RpcGetUserName where the Ex call is unavailable.
    """
    with tsts.TermSrvSession(smb, target_ip, do_kerberos) as ts:
        for sess in sessions:
            got_user = _enrich_via_ex(ts, sess, want_type, debug)
            if not got_user:
                _enrich_via_handle(ts, sess, want_type, debug)
    return sessions


def _ex_level1(pointer):
    """Return the LSM_SessionInfo_Level1 struct from a PLSMSESSIONINFORMATION_EX.

    impacket flattens this pointer's union referent onto the pointer itself, so
    the member is reachable directly as pointer['LSM_SessionInfo_Level1']. Older
    layouts expose it under the 'Data' referent instead; try both. Returns None
    for a NULL pointer / unexpected shape.
    """
    for container in (pointer, _deref(pointer)):
        if container is None:
            continue
        try:
            return container["LSM_SessionInfo_Level1"]
        except (KeyError, TypeError):
            continue
    return None


def _enrich_via_ex(ts, sess, want_type, debug):
    """Enrich one session through RpcGetSessionInformationEx. Returns True on data."""
    try:
        resp = ts.hRpcGetSessionInformationEx(sess.id)
    except DCERPCException as exc:
        if debug:
            logging.debug("GetSessionInformationEx(%d) failed: %s", sess.id, exc)
        return False
    level1 = _ex_level1(resp["LSMSessionInfoExPtr"])
    if level1 is None:
        if debug:
            logging.debug("GetSessionInformationEx(%d): empty/NULL info", sess.id)
        return False

    user = _clean_wstr(level1["UserName"])
    domain = _clean_wstr(level1["DomainName"])
    name = _clean_wstr(level1["SessionName"])
    if user:
        sess.user = user
    if domain:
        sess.domain = domain
    if name:
        sess.name = name  # live winstation name (e.g. RDP-Tcp#0 while connected)
    try:
        sess.state = int(level1["SessionState"])
    except (KeyError, ValueError, TypeError):
        pass
    if debug:
        logging.debug("session %d: name=%r user=%r domain=%r state=%s",
                      sess.id, sess.name, user, domain, sess.state_label)
    if want_type:
        _resolve_type(ts, sess, debug)
    return bool(user or domain)


def _enrich_via_handle(ts, sess, want_type, debug):
    """Fallback: RpcOpenSession + RpcGetUserName (legacy WinStationQueryInformationW path)."""
    try:
        hs = ts.hRpcOpenSession(sess.id)
    except DCERPCException as exc:
        if debug:
            logging.debug("OpenSession(%d) failed: %s", sess.id, exc)
        return
    try:
        try:
            uresp = ts.hRpcGetUserName(hs)
            sess.user = _clean_wstr(uresp["pszUserName"]) or sess.user
            sess.domain = _clean_wstr(uresp["pszDomain"]) or sess.domain
        except DCERPCException as exc:
            if debug:
                logging.debug("GetUserName(%d) failed: %s", sess.id, exc)
        if want_type:
            _resolve_type(ts, sess, debug)
    finally:
        try:
            ts.hRpcCloseSession(hs)
        except DCERPCException:
            pass


def _resolve_type(ts, sess, debug):
    try:
        tresp = ts.hRpcGetSessionType(sess.id)
        sess.sess_type = int(tresp["pSessionType"])
    except (DCERPCException, KeyError, ValueError, TypeError) as exc:
        if debug:
            logging.debug("GetSessionType(%d) failed: %s", sess.id, exc)


# --------------------------------------------------------------------------- #
# Formatting (matches qwinsta.exe row template)                                #
# --------------------------------------------------------------------------- #

# Column header as printed by the English qwinsta.exe.mui.  A leading column
# holds the '>' current-session marker (not meaningful for remote queries).
HEADER = " SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE"


def format_table(sessions, show_header=True):
    """Faithful reproduction of the native qwinsta row template (--classic)."""
    lines = []
    if show_header:
        lines.append(HEADER)
    for s in sorted(sessions, key=lambda x: x.id):
        marker = ">" if s.is_current else " "
        lines.append(
            "{marker}{name:<18}{user:<22}{sid:>5}  {state:<7} {type:<11} {device}".format(
                marker=marker,
                name=s.name[:18],
                user=s.user_label[:22],
                sid=s.id,
                state=s.state_label,
                type=s.type_label,
                device="",
            ).rstrip()
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Pretty formatting (default, human-readable)                                  #
# --------------------------------------------------------------------------- #

# Full-word state labels for the pretty view, keyed by WTS_CONNECTSTATE_CLASS.
STATE_LONG = {
    0: "Active",
    1: "Connected",
    2: "Connecting",
    3: "Shadowing",
    4: "Disconnected",
    5: "Idle",
    6: "Listening",
    7: "Reset",
    8: "Down",
    9: "Initializing",
}

# ANSI colour per state (name -> SGR code).
_COLORS = {
    "green": "32", "yellow": "33", "cyan": "36", "blue": "34",
    "red": "31", "magenta": "35", "dim": "2", "bold": "1", "reset": "0",
}
STATE_COLOR = {
    0: "green",    # Active
    1: "cyan",     # Connected
    2: "cyan",     # Connecting
    3: "magenta",  # Shadowing
    4: "yellow",   # Disconnected
    5: "dim",      # Idle
    6: "dim",      # Listening
    7: "red",      # Reset
    8: "red",      # Down
    9: "cyan",     # Initializing
}

PLACEHOLDER = "-"


def _paint(text, color, enabled):
    if not enabled or not color:
        return text
    return "\x1b[%sm%s\x1b[0m" % (_COLORS[color], text)


def _state_long(state):
    return STATE_LONG.get(int(state), str(int(state)))


def format_table_pretty(sessions, color=True, show_type=False):
    """Human-readable table: full-word states, placeholders, colour, summary."""
    sessions = sorted(sessions, key=lambda x: x.id)

    headers = ["ID", "SESSION", "USER", "STATE"]
    if show_type:
        headers.append("TYPE")

    # Build plain-text cells first so column widths ignore colour codes.
    rows = []
    for s in sessions:
        name = s.name if s.name else PLACEHOLDER
        user = s.user_label if s.user_label else PLACEHOLDER
        cells = [str(s.id), name, user, _state_long(s.state)]
        if show_type:
            cells.append(s.type_label or PLACEHOLDER)
        rows.append((s, cells))

    widths = [len(h) for h in headers]
    for _, cells in rows:
        for i, c in enumerate(cells):
            widths[i] = max(widths[i], len(c))

    def hline(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def render(cells, colorize_state=None, dim_empty=False):
        out = []
        for i, (c, w) in enumerate(zip(cells, widths)):
            # ID right-aligned, everything else left-aligned.
            pad = " " * (w - len(c))
            body = (pad + c) if i == 0 else (c + pad)
            if color:
                if i == 3 and colorize_state is not None:
                    body = _paint((pad + c) if i == 0 else (c + pad),
                                  colorize_state, True)
                elif dim_empty and c.strip() == PLACEHOLDER:
                    body = _paint(body, "dim", True)
            out.append(" " + body + " ")
        return "│" + "│".join(out) + "│"

    lines = [hline("┌", "┬", "┐")]
    lines.append(_bold_header(headers, widths, color))
    lines.append(hline("├", "┼", "┤"))
    for s, cells in rows:
        lines.append(render(cells, colorize_state=STATE_COLOR.get(int(s.state)),
                             dim_empty=True))
    lines.append(hline("└", "┴", "┘"))
    lines.append(_summary(sessions, color))
    return "\n".join(lines)


def _bold_header(headers, widths, color):
    out = []
    for i, (h, w) in enumerate(zip(headers, widths)):
        pad = " " * (w - len(h))
        body = (pad + h) if i == 0 else (h + pad)
        out.append(" " + _paint(body, "bold", color) + " ")
    return "│" + "│".join(out) + "│"


def _summary(sessions, color):
    users = [s for s in sessions if s.user_label]
    active = [s for s in users if int(s.state) == 0]
    disc = [s for s in users if int(s.state) == 4]
    parts = ["%d session%s" % (len(sessions), "" if len(sessions) == 1 else "s")]
    if not users:
        parts.append(_paint("no users signed in", "dim", color))
    else:
        who = ", ".join(
            "%s (%s)" % (s.user_label, _state_long(s.state).lower()) for s in users
        )
        parts.append("%d signed in: %s" % (len(users), who))
    tail = " · ".join(parts)
    if active:
        tail += "  " + _paint("● %d active" % len(active), "green", color)
    if disc:
        tail += "  " + _paint("○ %d disconnected" % len(disc), "yellow", color)
    return tail


# --------------------------------------------------------------------------- #
# Counters (--counter  ->  native WinStationGetTermSrvCountersValue)           #
# --------------------------------------------------------------------------- #

def show_counters(smb, target_ip, do_kerberos):
    """Terminal Services session counters: total/disconnected/reconnected.

    The native binary backs this with WinStationGetTermSrvCountersValue; over
    MS-TSTS the equivalent live figures come from RpcGetLoggedOnCount plus a
    state tally.
    """
    sessions = enumerate_sessions(smb, target_ip, do_kerberos)
    total = len(sessions)
    disconnected = sum(1 for s in sessions if int(s.state) == 4)
    active = sum(1 for s in sessions if int(s.state) == 0)
    with tsts.TermSrvSession(smb, target_ip, do_kerberos) as ts:
        try:
            logged = ts.hRpcGetLoggedOnCount()
            user_sessions = int(logged["pUserSessions"])
            device_sessions = int(logged["pDeviceSessions"])
        except (DCERPCException, KeyError):
            user_sessions = device_sessions = None

    out = []
    out.append("Terminal Services counters")
    out.append("  Total sessions created   : %d" % total)
    out.append("  Active sessions          : %d" % active)
    out.append("  Disconnected sessions    : %d" % disconnected)
    if user_sessions is not None:
        out.append("  Logged-on user sessions  : %d" % user_sessions)
        out.append("  Logged-on device sessions: %d" % device_sessions)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Connection helpers                                                           #
# --------------------------------------------------------------------------- #

def parse_target(target):
    """Parse impacket-style [[domain/]username[:password]@]host."""
    domain = username = password = ""
    remainder = target
    if "@" in remainder:
        creds, host = remainder.rsplit("@", 1)
    else:
        creds, host = "", remainder
    if "/" in creds:
        domain, creds = creds.split("/", 1)
    if ":" in creds:
        username, password = creds.split(":", 1)
    else:
        username = creds
    return domain, username, password, host


def connect(host, target_ip, domain, username, password, lmhash, nthash,
            aes_key, do_kerberos, dc_ip):
    smb = SMBConnection(host, target_ip or host)
    if do_kerberos:
        smb.kerberosLogin(username, password, domain, lmhash, nthash,
                          aes_key, kdcHost=dc_ip)
    else:
        smb.login(username, password, domain, lmhash, nthash)
    return smb


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        prog="qwinsta",
        description="List Remote Desktop / Terminal Services sessions on a remote "
                    "Windows host over MS-TSTS RPC.",
        epilog="examples:\n"
               "  qwinsta 'CORP/admin:Passw0rd@10.0.0.5'\n"
               "  qwinsta admin@10.0.0.5 -p Passw0rd\n"
               "  qwinsta -s 10.0.0.5 -u admin -d CORP\n"
               "  qwinsta admin@10.0.0.5 --counter\n"
               "  qwinsta admin@10.0.0.5 console        # filter one session",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", default=None,
                   help="[[domain/]username[:password]@]<host>")
    p.add_argument("filter", nargs="?", default=None,
                   help="optional sessionname | username | sessionid to match")

    p.add_argument("-s", "--server", dest="server", metavar="HOST",
                   help="target host (alternative to giving it in the target string)")
    p.add_argument("--counter", action="store_true",
                   help="show Terminal Services session counters instead of the list")
    p.add_argument("--type", dest="want_type", action="store_true",
                   help="resolve and show each session's TYPE column")
    p.add_argument("-c", "--classic", action="store_true",
                   help="faithful native qwinsta output instead of the pretty table")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI colour in the pretty table")
    p.add_argument("--no-header", action="store_true",
                   help="suppress the header row (classic mode)")

    # Credential flags (used with -s/--server, or to override the target string).
    p.add_argument("-u", "--username", default=None)
    p.add_argument("-p", "--password", default=None)
    p.add_argument("-d", "--domain", default="")

    # impacket-style auth.
    p.add_argument("-hashes", metavar="LMHASH:NTHASH", default=None,
                   help="NTLM hashes (pass-the-hash)")
    p.add_argument("-k", dest="kerberos", action="store_true",
                   help="use Kerberos auth (from ccache / -aesKey)")
    p.add_argument("-no-pass", dest="no_pass", action="store_true",
                   help="don't prompt for a password (use with -k or -hashes)")
    p.add_argument("-aesKey", default=None, help="AES key for Kerberos (128/256-bit)")
    p.add_argument("-dc-ip", dest="dc_ip", default=None, help="KDC / domain controller IP")
    p.add_argument("-target-ip", dest="target_ip", default=None,
                   help="connect to this IP instead of resolving the host name")

    p.add_argument("--debug", action="store_true", help="verbose RPC/debug logging")
    return p


def resolve_connection(args):
    """Work out host + credentials from the target string and/or the -s/--server flag."""
    domain = args.domain or ""
    username = args.username or ""
    password = args.password or ""
    host = None

    if args.target:
        d, u, pw, h = parse_target(args.target)
        if d:
            domain = d
        if u:
            username = u
        if pw:
            password = pw
        host = h
    if args.server:
        host = args.server
    return domain, username, password, host


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    domain, username, password, host = resolve_connection(args)
    if not host:
        sys.stderr.write("error: no target host. Use 'user@host' or -s/--server host.\n")
        return 2

    lmhash = nthash = ""
    if args.hashes:
        if ":" in args.hashes:
            lmhash, nthash = args.hashes.split(":", 1)
        else:
            nthash = args.hashes

    if (not password and not args.no_pass and not nthash and not args.kerberos
            and not args.aesKey):
        import getpass
        try:
            password = getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            return 2

    try:
        smb = connect(host, args.target_ip, domain, username, password,
                      lmhash, nthash, args.aesKey, args.kerberos, args.dc_ip)
    except Exception as exc:  # noqa: BLE001 - surface a clean message
        sys.stderr.write("error: could not connect/authenticate to %s: %s\n" % (host, exc))
        return 1

    target_ip = args.target_ip or host
    try:
        if args.counter:
            print(show_counters(smb, target_ip, args.kerberos))
            return 0

        sessions = enumerate_sessions(smb, target_ip, args.kerberos)
        enrich_sessions(smb, target_ip, args.kerberos, sessions,
                        want_type=args.want_type, debug=args.debug)

        if args.filter:
            f = args.filter.lower()
            sessions = [s for s in sessions
                        if f == str(s.id)
                        or f == s.name.lower()
                        or f == s.user.lower()]

        if not sessions:
            # Native qwinsta prints nothing / an error; keep it quiet but non-fatal.
            return 0

        if args.classic:
            print(format_table(sessions, show_header=not args.no_header))
        else:
            use_color = sys.stdout.isatty() and not args.no_color
            print(format_table_pretty(sessions, color=use_color,
                                      show_type=args.want_type))
        return 0
    except (smb3.SessionError, smbconnection.SessionError) as exc:
        msg = str(exc)
        if "ACCESS_DENIED" in msg:
            sys.stderr.write(
                "error: access denied opening the Terminal Services RPC pipe on %s.\n"
                "       Remote session enumeration requires administrative rights.\n" % host)
        else:
            sys.stderr.write("error: SMB/RPC transport failed: %s\n" % msg)
        return 1
    except DCERPCException as exc:
        sys.stderr.write("error: RPC call failed: %s\n" % exc)
        return 1
    finally:
        try:
            smb.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
