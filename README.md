# pyqwinsta

A python implementation of the **remote** behaviour of Windows' `qwinsta.exe`. It lists the RDP/TS sessions of a remote Windows machine by speaking the real **MS-TSTS** RPC protocol over SMB.

```
$ qwinsta 'CORP/Administrator:Passw0rd@10.0.0.5'
┌───────┬───────────┬───────────────┬──────────────┐
│    ID │ SESSION   │ USER          │ STATE        │
├───────┼───────────┼───────────────┼──────────────┤
│     0 │ Services  │ -             │ Disconnected │
│     2 │ RDP-Tcp#0 │ administrator │ Active       │
│ 65536 │ rdp-tcp   │ -             │ Listening    │
└───────┴───────────┴───────────────┴──────────────┘
3 sessions · 1 signed in: administrator (active)  ● 1 active
```

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Requires Python 3.8+ and [impacket](https://github.com/fortra/impacket)
(which provides `impacket.dcerpc.v5.tsts`, the MS-TSTS implementation).

## Usage

```
qwinsta [[domain/]username[:password]@]<host> [filter] [options]
qwinsta -s <host> -u <user> -p <pass> -d <domain> [filter] [options]
```

The target host and credentials can be given either as a single
`user@host` string or with separate `-s/--server`, `-u`, `-p`, `-d` flags.

### Examples

```bash
qwinsta 'CORP/admin:Passw0rd@10.0.0.5'           # password auth
qwinsta admin@dc01 -hashes :8846f7eaee8fb117...  # pass-the-hash
qwinsta admin@dc01 -k -no-pass                   # Kerberos ticket from ccache
qwinsta -s 10.0.0.5 -u admin -p Passw0rd -d CORP # separate flags
qwinsta admin@10.0.0.5 --counter                 # session counters
qwinsta admin@10.0.0.5 console                   # filter one session
```

## How it works

The protocol internals are documented in [INTERNALS.md](INTERNALS.md).

## Test

```bash
. .venv/bin/activate
python -m unittest test_qwinsta -v
```