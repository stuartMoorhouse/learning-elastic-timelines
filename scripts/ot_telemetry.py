#!/usr/bin/env python3
"""Generate synthetic OT telemetry as Elasticsearch bulk NDJSON on stdout.

Everything here is invented (sites, hosts, IPs, accounts), but the documents are shaped like the real
Elastic integrations that would produce them, and use ECS fields wherever ECS has one:

  zeek.modbus / zeek.connection   Zeek on an OT network sensor (Elastic Zeek integration fields)
  system.security                 Windows Security events 4624/4625 (Elastic System integration)
  endpoint.events.*               Elastic Defend process, network and file events (plus labels.bus_type on USB processes)
  panw.panos                      DMZ firewall traffic logs (Palo Alto PAN-OS integration, ECS fields only)

Fields outside ECS are custom fields modelled per the ECS guidance: zeek.* and winlog.* (the integrations' own) and labels.* (the device bus type).
Zeek's Modbus log holds the function name, not register addresses or values, so none are invented.

Each event has a fixed _id so timelines can pin it. Times are relative to now.

Scenarios (one function each):
  s1  Writes to a line-2 controller from a read-only host (T0836)            true positive
  s2  Remote desktop logons to the HMI from the IT network (T0886)           true positive
  s3  Unknown device scanning the controller subnet (T0846)                  open handover
  s4  Engineering software sessions to a controller in a change window       accepted behaviour
  s5  Executables run from removable media on the engineering ws (T0847)     true positive
  s6  Outbound traffic from the OT zone: only scheduled, documented flows    clean
"""
import base64
import hashlib
import json
import random
import socket
import struct
import sys
from datetime import datetime, timedelta, timezone

NS = "ot"  # data stream namespace: logs-<dataset>-ot, so the real demo VM streams stay untouched
_rng = random.Random(1102)
_now = datetime.now(timezone.utc).replace(microsecond=0)
_ingested = _now.strftime("%Y-%m-%dT%H:%M:%SZ")

# Asset inventory (name -> ip). Network sensors do not know names; analysts map them with this list.
A = {
    "ot-eng-ws-01": "10.50.1.20",   # engineering workstation, authorised writer
    "ot-hmi-01": "10.50.2.10",      # operator HMI, authorised writer
    "ot-hist-01": "10.50.2.30",     # historian, read-only by design
    "plc-line2-01": "10.50.3.11",   # controller, line 2 pump skid (Modbus)
    "plc-line2-02": "10.50.3.12",   # controller, line 2 mixer (S7)
    "ot-jump-01": "10.50.0.5",      # jump host, the only approved remote path into the zone
    "ot-time-01": "10.50.0.2",      # internal time server
}
B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def ts(offset):
    t = _now + timedelta(seconds=offset)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % _rng.randint(0, 999)


def community_id(src, dst, sport, dport, proto):
    a, b = socket.inet_aton(src), socket.inet_aton(dst)
    if (a, sport) > (b, dport):
        a, b, sport, dport = b, a, dport, sport
    data = struct.pack("!H", 0) + a + b + struct.pack("!BBHH", proto, 0, sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()


def sha256():
    return "".join(_rng.choice("0123456789abcdef") for _ in range(64))


def uid(prefix="C"):
    return prefix + "".join(_rng.choice(B62) for _ in range(17))


def base(dataset, module, ecs, category, etypes, action, offset, outcome=None):
    ev = {"kind": "event", "category": category, "type": etypes, "action": action,
          "dataset": dataset, "module": module, "ingested": _ingested}
    if outcome:
        ev["outcome"] = outcome
    t = ts(offset)
    ev["created"] = t
    return {"@timestamp": t, "ecs": {"version": ecs}, "data_stream": {"type": "logs", "dataset": dataset, "namespace": NS}, "event": ev}


# ---------------------------------------------------------------- Zeek (OT network sensor)
def zeek_modbus(_id, offset, src, dst, function):
    sport = _rng.randint(49152, 65000)
    d = base("zeek.modbus", "zeek", "8.11.0", ["network"], ["connection", "protocol"], "modbus", offset)
    d["network"] = {"protocol": "modbus", "transport": "tcp", "direction": "internal",
                    "community_id": community_id(A[src] if src in A else src, A[dst], sport, 502, 6)}
    sip = A.get(src, src)
    d["source"] = {"address": sip, "ip": sip, "port": sport}
    d["destination"] = {"address": A[dst], "ip": A[dst], "port": 502}
    d["related"] = {"ip": [sip, A[dst]]}
    d["zeek"] = {"session_id": uid(), "modbus": {"function": function}}
    d["tags"] = ["zeek"]
    return _id, d


def zeek_conn(_id, offset, sip, dip, dport, state, mac=None, protocol=None):
    sport = _rng.randint(49152, 65000)
    d = base("zeek.connection", "zeek", "8.11.0", ["network"], ["connection", "end"], "network_flow", offset,
             "success" if state == "SF" else "failure")
    states = {"SF": ("ShADadFf", "Normal establishment and termination."),
              "S0": ("S", "Connection attempt seen, no reply."),
              "REJ": ("Sr", "Connection attempt rejected.")}
    hist, msg = states[state]
    net = {"transport": "tcp", "direction": "internal", "community_id": community_id(sip, dip, sport, dport, 6)}
    if protocol:
        net["protocol"] = protocol
    sb, db, sp, dp = (0, 0, 1, 0) if state == "S0" else (0, 0, 1, 1) if state == "REJ" else (_rng.randint(80, 400), _rng.randint(80, 400), 6, 5)
    net["bytes"] = sb + db
    net["packets"] = sp + dp
    d["network"] = net
    d["source"] = {"address": sip, "ip": sip, "port": sport, "bytes": sb, "packets": sp}
    if mac:
        d["source"]["mac"] = mac
    d["destination"] = {"address": dip, "ip": dip, "port": dport, "bytes": db, "packets": dp}
    if state != "S0":
        d["event"]["duration"] = _rng.randint(2_000_000, 90_000_000)
    d["related"] = {"ip": [sip, dip]}
    d["zeek"] = {"session_id": uid(), "connection": {"state": state, "state_message": msg, "history": hist,
                                                     "local_orig": True, "local_resp": True, "missed_bytes": 0}}
    d["tags"] = ["zeek"]
    return _id, d


# ---------------------------------------------------------------- Windows Security (System integration)
def winlogon(_id, offset, host, code, ltype, src_ip, src_name, user, ok_reason=None):
    ok = code == "4624"
    d = base("system.security", "system", "8.11.0", ["authentication"], ["start"],
             "logged-in" if ok else "logon-failed", offset, "success" if ok else "failure")
    d["event"]["code"] = code
    d["event"]["provider"] = "Microsoft-Windows-Security-Auditing"
    d["agent"] = {"name": host, "type": "filebeat", "version": "9.5.3"}
    d["host"] = {"name": host, "hostname": host, "os": {"family": "windows", "platform": "windows", "type": "windows", "name": "Windows Server 2022 Standard"}}
    d["log"] = {"level": "information"}
    d["process"] = {"pid": 0}
    d["user"] = {"id": "S-1-5-21-1004336348-1177238915-682003330-1004" if ok else "S-1-0-0", "name": user, "domain": host.upper()}
    num = {"Interactive": "2", "Network": "3", "Service": "5", "RemoteInteractive": "10"}[ltype]
    ed = {"LogonType": num, "TargetUserName": user}
    wl = {"channel": "Security", "computer_name": host, "event_id": code, "provider_name": "Microsoft-Windows-Security-Auditing",
          "record_id": str(_rng.randint(1000, 90000)), "task": "Logon", "logon": {"type": ltype}, "event_data": ed}
    if src_ip:
        d["source"] = {"ip": src_ip, "port": _rng.randint(49152, 65000)}
        d["related"] = {"ip": [src_ip], "user": [user]}
        if src_name:
            d["source"]["domain"] = src_name
    else:
        d["related"] = {"user": [user]}
    if ltype == "RemoteInteractive":
        ed.update({"AuthenticationPackageName": "Negotiate", "LogonProcessName": "User32 "})
    if ok:
        wl["logon"]["id"] = "0x%x" % _rng.randint(0x100000, 0xFFFFFF)
        wl["keywords"] = ["Audit Success"]
    else:
        ed.update({"FailureReason": "Unknown user name or bad password.", "Status": "0xc000006d", "SubStatus": "0xc000006a"})
        wl["logon"]["failure"] = {"reason": "Unknown user name or bad password.",
                                  "status": "This is either due to a bad username or authentication information",
                                  "sub_status": "Account logon with incorrect password"}
        wl["keywords"] = ["Audit Failure"]
    d["winlog"] = wl
    return _id, d


# ---------------------------------------------------------------- Elastic Defend
ENG = "ot-eng-ws-01"
TIA = r"C:\Program Files\Siemens\Automation\Portal V18\Bin\Siemens.Automation.Portal.exe"
EXPLORER = r"C:\Windows\explorer.exe"


def _endpoint(d, host, user="engineer1"):
    d["agent"] = {"id": "0b6d1f5a-3c2e-4f60-9a64-5a2e8b0c11d7", "type": "endpoint", "version": "9.5.3"}
    d["host"] = {"name": host, "hostname": host, "os": {"type": "windows", "family": "windows", "platform": "windows"}}
    d["event"]["id"] = "".join(_rng.choice(B62) for _ in range(20)) + "++"
    d["user"] = {"name": user, "domain": host.upper(), "id": "S-1-5-21-1004336348-1177238915-682003330-1105"}


def d_process(_id, offset, name, exe, parent_name, parent_exe, args, usb=None, signed=True, pid=None):
    d = base("endpoint.events.process", "endpoint", "8.10.0", ["process"], ["start"], ["start"], offset, "unknown")
    _endpoint(d, ENG)
    d["process"] = {"entity_id": "".join(_rng.choice(B62) for _ in range(22)), "pid": pid or _rng.randint(1000, 9000), "name": name,
                    "executable": exe, "args": args, "command_line": " ".join('"%s"' % a if " " in a else a for a in args),
                    "working_directory": exe.rsplit("\\", 1)[0] + "\\",
                    "hash": {"sha256": sha256()},
                    "code_signature": ({"exists": True, "status": "trusted", "subject_name": "Siemens AG", "trusted": True} if signed else {"exists": False}),
                    "parent": {"name": parent_name, "executable": parent_exe, "pid": _rng.randint(1000, 9000)}}
    if usb:
        # custom fields under ECS labels (ECS custom-fields guidance): the device the executable ran from
        d["labels"] = {"bus_type": "usb", "dos_name": usb}
    d["message"] = "Endpoint process event"
    return _id, d


def d_network(_id, offset, process_name, exe, dst_ip, dport, sent, received, duration_s):
    d = base("endpoint.events.network", "endpoint", "8.10.0", ["network"], ["start", "end"],
             ["connection_attempted", "disconnect_received"], offset, "unknown")
    _endpoint(d, ENG)
    sport = _rng.randint(49152, 65000)
    d["network"] = {"direction": "egress", "transport": "tcp", "type": "ipv4",
                    "community_id": community_id(A[ENG], dst_ip, sport, dport, 6)}
    d["source"] = {"address": A[ENG], "ip": A[ENG], "port": sport, "bytes": sent}
    d["destination"] = {"address": dst_ip, "ip": dst_ip, "port": dport, "bytes": received}
    d["process"] = {"entity_id": "".join(_rng.choice(B62) for _ in range(22)), "pid": _rng.randint(1000, 9000), "name": process_name, "executable": exe}
    d["event"]["duration"] = duration_s * 1_000_000_000
    return _id, d


def d_file(_id, offset, path, proc_name, proc_exe, size):
    d = base("endpoint.events.file", "endpoint", "8.10.0", ["file"], ["creation"], ["creation"], offset, "unknown")
    _endpoint(d, ENG)
    d["file"] = {"path": path, "name": path.split("\\")[-1], "extension": path.rsplit(".", 1)[-1], "size": size}
    d["process"] = {"entity_id": "".join(_rng.choice(B62) for _ in range(22)), "pid": _rng.randint(1000, 9000), "name": proc_name, "executable": proc_exe}
    return _id, d


# ---------------------------------------------------------------- PAN-OS firewall (ECS fields only)
def fw(_id, offset, src, dst_ip, port, transport, app, rule, direction, sent, received, duration_s):
    sport = _rng.randint(49152, 65000)
    d = base("panw.panos", "panw", "8.11.0", ["network"], ["connection", "allowed", "end"], "flow_ended", offset, "success")
    proto = 6 if transport == "tcp" else 17
    d["observer"] = {"name": "ot-fw-dmz", "type": "firewall", "vendor": "Palo Alto Networks", "product": "PAN-OS"}
    d["network"] = {"direction": direction, "transport": transport, "iana_number": str(proto), "application": app,
                    "bytes": sent + received, "packets": max(2, (sent + received) // 700),
                    "community_id": community_id(src, dst_ip, sport, port, proto)}
    d["source"] = {"address": src, "ip": src, "port": sport, "bytes": sent}
    d["destination"] = {"address": dst_ip, "ip": dst_ip, "port": port, "bytes": received}
    d["rule"] = {"name": rule}
    d["event"]["duration"] = duration_s * 1_000_000_000
    d["related"] = {"ip": [src, dst_ip]}
    return _id, d


# ---------------------------------------------------------------- baseline
def baseline():
    out = []
    plc1, plc2 = "plc-line2-01", "plc-line2-02"
    for i in range(0, 6 * 3600, 30):     # HMI polls both controllers over Modbus
        out.append(zeek_modbus("ot-base-hmi1-%05d" % (i // 30), -i, "ot-hmi-01", plc1, "READ_HOLDING_REGISTERS"))
    for i in range(0, 6 * 3600, 60):     # the historian reads only
        out.append(zeek_modbus("ot-base-hist-%05d" % (i // 60), -i - 3, "ot-hist-01", plc1, "READ_HOLDING_REGISTERS"))
    for k, off in enumerate([-5 * 3600, -4 * 3600 - 900, -3 * 3600 - 1800]):   # authorised operator writes from the HMI
        out.append(zeek_modbus("ot-base-hmiw-%d" % k, off, "ot-hmi-01", plc1, "WRITE_SINGLE_REGISTER"))
    for k in range(5):                    # maintenance writes from the engineering workstation
        out.append(zeek_modbus("ot-base-engw-%d" % k, -2 * 3600 - 600 * k, "ot-eng-ws-01", plc1,
                               ["WRITE_SINGLE_REGISTER", "WRITE_MULTIPLE_REGISTERS", "WRITE_SINGLE_COIL"][k % 3]))
    for i in range(0, 6 * 3600, 300):     # Zeek connection records for the polling sessions
        out.append(zeek_conn("ot-base-fl1-%04d" % (i // 300), -i - 11, A["ot-hmi-01"], A[plc1], 502, "SF", protocol="modbus"))
    for i in range(0, 6 * 3600, 600):
        out.append(zeek_conn("ot-base-fl2-%04d" % (i // 600), -i - 17, A["ot-hist-01"], A[plc1], 502, "SF", protocol="modbus"))
    for i in range(0, 6 * 3600, 900):
        out.append(zeek_conn("ot-base-fl3-%04d" % (i // 900), -i - 23, A["ot-hmi-01"], A[plc2], 102, "SF"))
    # logons on the HMI: approved jump host sessions, operators at the console, service logons
    for k, off in enumerate([-5 * 3600 - 900, -3 * 3600 - 2400, -1 * 3600 - 600]):
        out.append(winlogon("ot-base-rdp-%d" % k, off, "ot-hmi-01", "4624", "RemoteInteractive", A["ot-jump-01"], "OT-JUMP-01", "ops-jump"))
    for k, off in enumerate([-5 * 3600 - 1200, -1 * 3600 - 1500]):
        out.append(winlogon("ot-base-con-%d" % k, off, "ot-hmi-01", "4624", "Interactive", None, None, "operator1"))
    for k in range(6):
        out.append(winlogon("ot-base-svc-%d" % k, -k * 3500 - 40, "ot-hmi-01", "4624", "Service", None, None, "SYSTEM"))
    # engineering workstation: TIA Portal opened for offline work, no controller session
    for k, off in enumerate([-5 * 3600 - 1800, -100 * 60]):
        out.append(d_process("ot-base-eng-%d" % k, off, "Siemens.Automation.Portal.exe", TIA, "explorer.exe", EXPLORER, [TIA]))
    # firewall: internal traffic (noise) and the two scheduled outbound flows
    for i in range(0, 6 * 3600, 600):
        out.append(fw("ot-base-fwi-%04d" % (i // 600), -i - 31, A["ot-hmi-01"], A[plc1], 502, "tcp", "modbus", "OT-INTERNAL", "internal", 640, 480, 2))
    for i in range(0, 6 * 3600, 3600):    # NTP to an external pool, hourly
        out.append(fw("ot-fw-ntp-%02d" % (i // 3600), -i - 120, A["ot-time-01"], "203.0.113.5", 123, "udp", "ntp", "OT-DMZ-NTP-OUT", "outbound", 76, 76, 1))
    for i in range(0, 6 * 3600, 1800):    # historian replication to the vendor cloud, every 30 minutes
        out.append(fw("ot-fw-rep-%02d" % (i // 1800), -i - 240, A["ot-hist-01"], "198.51.100.20", 443, "tcp", "ssl", "OT-DMZ-HIST-REPL", "outbound",
                      48000 + _rng.randint(-900, 900), 3200 + _rng.randint(-200, 200), 12))
    return out


# ---------------------------------------------------------------- scenarios
def s1():
    """The historian, which only reads, sends six Modbus write requests to plc-line2-01."""
    t0 = -3 * 3600
    funcs = ["WRITE_SINGLE_REGISTER", "WRITE_SINGLE_REGISTER", "WRITE_MULTIPLE_REGISTERS",
             "WRITE_SINGLE_COIL", "WRITE_SINGLE_REGISTER", "WRITE_SINGLE_COIL"]
    offs = [0, 120, 190, 260, 330, 400]
    return [zeek_modbus("ot-s1-w%d" % (i + 1), t0 + offs[i], "ot-hist-01", "plc-line2-01", funcs[i]) for i in range(6)]


def s2():
    """A vendor account fails four times, then logs on over RDP to the HMI from an IT address."""
    t0 = -(2 * 3600 + 20 * 60)
    src, name, h = "10.20.4.77", "ITWS-0417", "ot-hmi-01"
    out = [winlogon("ot-s2-f%d" % i, t0 + 12 * i, h, "4625", "RemoteInteractive", src, name, "svc-vendor") for i in range(1, 5)]
    out.append(winlogon("ot-s2-ok1", t0 + 60, h, "4624", "RemoteInteractive", src, name, "svc-vendor"))
    out.append(winlogon("ot-s2-ok2", t0 + 25 * 60, h, "4624", "RemoteInteractive", src, name, "svc-vendor"))
    return out


def s3():
    """An unknown device sweeps 10.50.3.1-24 on Modbus, S7 and EtherNet/IP ports."""
    t0 = -90 * 60
    src, mac = "10.50.2.99", "00-1B-21-AA-BB-99"
    live = {"10.50.3.11": 502, "10.50.3.12": 102, "10.50.3.20": 44818}   # live hosts, one open port each
    out, n = [], 0
    for host in range(1, 25):
        dst = "10.50.3.%d" % host
        for port in (502, 102, 44818):
            n += 1
            if dst in live:
                state = "SF" if live[dst] == port else "REJ"
            else:
                state = "S0"
            out.append(zeek_conn("ot-s3-%03d" % n, t0 + n * 1.2, src, dst, port, state, mac=mac,
                                 protocol="modbus" if (state == "SF" and port == 502) else None))
    return out


def s4():
    """TIA Portal on the engineering workstation opens three sessions to plc-line2-02 (S7, port 102)."""
    t0 = -4 * 3600
    return [
        d_process("ot-s4-p1", t0 - 600, "Siemens.Automation.Portal.exe", TIA, "explorer.exe", EXPLORER, [TIA]),
        d_network("ot-s4-n1", t0, "Siemens.Automation.Portal.exe", TIA, A["plc-line2-02"], 102, 1_840_000, 96_000, 270),
        d_network("ot-s4-n2", t0 + 330, "Siemens.Automation.Portal.exe", TIA, A["plc-line2-02"], 102, 38_000, 22_000, 45),
        d_network("ot-s4-n3", t0 + 420, "Siemens.Automation.Portal.exe", TIA, A["plc-line2-02"], 102, 12_000, 9_000, 20),
    ]


def s5():
    """A USB drive is plugged into the engineering workstation; two executables on it run, one drops a lookalike svchost32.exe."""
    t0 = -70 * 60
    autorun, update = r"E:\ProjectBackup\autorun.exe", r"E:\ProjectBackup\update.exe"
    drop = r"C:\Users\Public\svchost32.exe"
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return [
        d_process("ot-s5-p1", t0, "autorun.exe", autorun, "explorer.exe", EXPLORER, [autorun], usb="E:", signed=False),
        d_process("ot-s5-p2", t0 + 3, "update.exe", update, "autorun.exe", autorun, [update], usb="E:", signed=False),
        d_file("ot-s5-f1", t0 + 7, drop, "update.exe", update, 187392),
        d_process("ot-s5-p3", t0 + 11, "svchost32.exe", drop, "update.exe", update, [drop], signed=False),
        d_process("ot-s5-p4", t0 + 40, "powershell.exe", ps, "svchost32.exe", drop,
                  [ps, "-nop", "-w", "hidden", "-c", "Get-ChildItem C:\\Projects"]),
    ]


def main():
    docs = baseline() + s1() + s2() + s3() + s4() + s5()
    docs.sort(key=lambda d: d[1]["@timestamp"])
    for _id, doc in docs:
        index = "logs-%s-%s" % (doc["data_stream"]["dataset"], NS)
        sys.stdout.write(json.dumps({"create": {"_index": index, "_id": _id}}) + "\n")
        sys.stdout.write(json.dumps(doc) + "\n")


if __name__ == "__main__":
    main()
