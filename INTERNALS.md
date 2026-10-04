# How the native `qwinsta.exe` works internally

This project was reverse-engineered from the supplied `qwinsta.exe`
(PE32+, x86-64). Its import table and `.rdata` tell the whole story.

## 1. Imports (`WINSTA.dll` / `UTILDLL.dll`)

```
WINSTA.dll
    WinStationOpenServerW          <- bind to a (remote) Terminal Server
    WinStationOpenServerExW
    WinStationEnumerateW           <- enumerate sessions (id, state, winstation name)
    WinStationQueryInformationW    <- per-session details (user, state, type, times)
    WinStationGetAllSessionsEx
    WinStationGetTermSrvCountersValue   <- backs the /COUNTER switch
    WinStationFreeMemory / WinStationFreeEXECENVDATAEX
UTILDLL.dll
    StrConnectState / StrAsyncConnectState   <- map the state enum to "Active"/"Disc"/...
```

The `.rdata` row template that formats the table is literally:

```
%-24s  %-20s  %5d  %-6s  %-10s  %-8s      (SESSIONNAME USERNAME ID STATE TYPE DEVICE)
```

(The column **titles** are not in the EXE; they live in the external
`qwinsta.exe.mui` resource-only DLL. The EXE itself carries only `MUI`,
`VERSION` and `MANIFEST` resources — no string/message table.)

## 2. What those WINSTA.dll calls do on the wire

`WINSTA.dll` is a thin client stub. When you pass `/SERVER:host`, it does
**not** use a private protocol — it drives the documented
**[MS-TSTS] Terminal Services Terminal Server Runtime Interface Protocol**
over MSRPC. The RPC interfaces are reached through named pipes on the
remote host, carried inside SMB on TCP/445:

| WINSTA.dll call              | MS-TSTS interface      | Pipe                      | Interface UUID                             |
|------------------------------|------------------------|---------------------------|--------------------------------------------|
| `WinStationOpenServerW`      | (bind / LegacyAPI)     | `\pipe\Ctx_WinStation_API_service` | `5ca4a760-ebb1-11cf-8611-00a0245420ed` |
| `WinStationEnumerateW`       | **TermSrvEnumeration** | `\pipe\LSM_API_service`   | `88143fd0-c28d-4b2b-8fef-8d882f6a9390`     |
| `WinStationQueryInformationW`| **TermSrvSession**     | `\pipe\LSM_API_service`   | `484809d6-4239-471b-b5bc-61df8c23ac48`     |

## 3. The exact sequence this tool reproduces

```
SMB3 negotiate + session setup + tree connect to IPC$        (TCP/445)
│
├─ bind TermSrvEnumeration (LSM_API_service), PKT_PRIVACY
│     RpcOpenEnum              (opnum 0)  -> enum handle
│     RpcGetEnumResultEx       (opnum 9, Level=1)
│          -> array of { SessionId, State, WinStationName }
│     RpcCloseEnum             (opnum 1)
│
└─ bind TermSrvSession (LSM_API_service), PKT_PRIVACY
      for each SessionId:
          RpcOpenSession       (opnum 0)  -> session handle
          RpcGetUserName       (opnum 5)  -> (Domain, User)     [WinStationQueryInformationW]
          RpcGetState          (opnum 7)  -> WTS_CONNECTSTATE
          RpcGetSessionType    (opnum 16) -> SESSIONTYPE        [--type only]
          RpcCloseSession      (opnum 1)
```

`RpcGetEnumResultEx` returns a `SESSIONENUM_LEVEL1` per session:

```c
typedef struct {
    LONG               SessionId;   // 0 = Services, 1 = Console, 65536 = listener...
    WINSTATIONSTATECLASS State;     // WTS_CONNECTSTATE_CLASS
    WCHAR              Name[33];     // "services", "console", "rdp-tcp#0", ...
} SESSIONENUM_LEVEL1;
```

## 4. The STATE column (`UTILDLL!StrConnectState`)

`WTS_CONNECTSTATE_CLASS` → the short labels `qwinsta` prints:

| Value | Enum                | Label    |
|-------|---------------------|----------|
| 0     | `WTSActive`         | `Active` |
| 1     | `WTSConnected`      | `Conn`   |
| 2     | `WTSConnectQuery`   | `ConnQ`  |
| 3     | `WTSShadow`         | `Shadow` |
| 4     | `WTSDisconnected`   | `Disc`   |
| 5     | `WTSIdle`           | `Idle`   |
| 6     | `WTSListen`         | `Listen` |
| 7     | `WTSReset`          | `Reset`  |
| 8     | `WTSDown`           | `Down`   |
| 9     | `WTSInit`           | `Init`   |

## 5. Why it needs administrative rights

Opening `\pipe\LSM_API_service` and binding the TermSrv* interfaces is an
ACL-protected operation. An anonymous / low-privilege caller is refused with
`STATUS_ACCESS_DENIED` at the SMB `create` of the pipe — exactly what native
`qwinsta /SERVER` does when you lack the rights. (Verified against a live
host: a null session reaches the pipe and is denied, confirming the path is
correct.)

## References

- **[MS-TSTS]** Terminal Services Terminal Server Runtime Interface Protocol
- **[MS-RDPBCGR]**, **[MS-RDPERP]** (session types / RAIL)
- `WTS_CONNECTSTATE_CLASS`, `WTSEnumerateSessions` (Win32 Terminal Services API)
