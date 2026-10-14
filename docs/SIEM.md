# SIEM export and MITRE ATT&CK for ICS

The Rust gateway (`robot_firewall`) streams every incident to a SIEM as
syslog over UDP. Each incident is tagged with its **MITRE ATT&CK for ICS**
technique and tactic, so it lands in your existing detections, dashboards and
reports like any other industrial security event.

## Enable it

On the gateway, in `deploy/nanopi/firewall.env`:

```bash
SIEM_SYSLOG=udp://192.168.1.60:514   # your collector
SIEM_FORMAT=cef                      # or json
```

Then re-run `sudo ./deploy/nanopi/setup_nanopi.sh`. It also adds an nftables
rule allowing **only** that destination out of the WiFi interface.

Outside the deploy scripts, the same settings are parameters:

```bash
robot_firewall --config firewall_params.yaml --set siem_syslog=udp://192.168.1.60:514 --set siem_format=cef
```

UDP is deliberate: if the collector is down, the firewall loses events, never
commands.

## Formats

**CEF** (Splunk, Microsoft Sentinel, IBM QRadar, ArcSight), in RFC 5424
syslog, facility local4:

```
<164>1 2026-10-14T06:40:00.250Z nanopi-r5s robot_firewall - UNAUTHORIZED_PUBLISHER - CEF:0|RoboShield|robot_firewall|0.3.0|UNAUTHORIZED_PUBLISHER|command from a publisher that is not allowlisted|6|rt=1791900000250 dvchost=nanopi-r5s act=DROPPED cnt=11 msg=UNAUTHORIZED_PUBLISHER: command from a publisher that is not allowlisted (source: intruder); 11 msg(s) dropped cs1Label=firewallMode cs1=ARMED suser=intruder cs2Label=mitreTechniqueId cs2=T1692.001 cs3Label=mitreTechnique cs3=Command Message cs4Label=mitreTactic cs4=Impair Process Control cs5Label=mitreFramework cs5=ATT&CK for ICS v20
```

**JSON** (Elastic, or any collector that parses JSON). It's the same line the
gateway writes to `/var/log/robot_firewall/incidents.jsonl`:

```json
{"action":"DROPPED","attack":"UNAUTHORIZED_PUBLISHER","count":11,"detail":"command from a publisher that is not allowlisted","mitre_framework":"ATT&CK for ICS v20","mitre_tactic":"Impair Process Control","mitre_technique":"Command Message","mitre_technique_id":"T1692.001","mode":"ARMED","severity":"WARN","source":"intruder","summary":"UNAUTHORIZED_PUBLISHER: ...; 11 msg(s) dropped","time":1791900000.25}
```

Severity: CEF 4 for clamped, 6 for dropped, 8 for critical alerts and 9 for
lockdown. Syslog uses warning (4) and error (3).

## MITRE ATT&CK for ICS mapping

Verified against MITRE's official STIX data, ics-attack **v20**. In v20,
T0855 *Unauthorized Command Message* and T0856 *Spoof Reporting Message* were
revoked in favour of T1692.001 and T1692.002.

| Firewall incident | Technique | Tactic |
|---|---|---|
| `MALFORMED`, `INVALID_VALUE`, `LIMIT_VIOLATION`, `STEP_JUMP`, `REPLAY`, `UNAUTHORIZED_PUBLISHER` | T1692.001 Command Message | Impair Process Control |
| `FLOOD` | T0814 Denial of Service | Inhibit Response Function |
| `ROGUE_DEVICE_ON_ROBOT_LAN` (extra commander on the robot LAN) | T0848 Rogue Master | Initial Access |
| `STATE_SPOOFING` (extra publisher of robot state) | T1692.002 Reporting Message | Evasion |
| `STATE_GUARD` (robot reports a position out of bounds) | T0880 Loss of Safety | Impact |
| `STATE_STALE` (robot telemetry lost) | T0815 Denial of View | Impact |
| `NETWORK_PROBE` (nftables blocked packets) | T0846 Remote System Discovery | Discovery |

`LOCKDOWN` and `BLOCKED_IN_LOCKDOWN` are the firewall's *responses*, not attack
techniques, so they carry no tag.

The tags also appear in the incident log, on `/firewall/events` (key-values
`mitre_technique_id`, `mitre_technique`, `mitre_tactic`), and in the console's
incident table.

## Collector examples

**Splunk** (`inputs.conf`; Splunk's CEF add-ons extract the `cs*` fields):

```ini
[udp://514]
sourcetype = cef
index = ot_security
connection_host = ip
```

**Elastic** (Filebeat or Elastic Agent; use `SIEM_FORMAT=json`):

```yaml
filebeat.inputs:
  - type: syslog
    format: rfc5424
    protocol.udp:
      host: "0.0.0.0:514"
    processors:
      - decode_json_fields:
          fields: ["message"]
          target: "roboshield"
```

**rsyslog** (forward to a file or relay):

```
module(load="imudp")
input(type="imudp" port="514" ruleset="roboshield")
ruleset(name="roboshield") { action(type="omfile" file="/var/log/roboshield.log") }
```

**Quick test without a SIEM:**

```bash
nc -klu 514
```
