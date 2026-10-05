# Strata

Strata is a local-first network-flow dashboard with live Linux interface capture, CSV flow analysis, configurable anomaly scoring, and an in-browser alert table. Its responsive interface has dedicated Overview, Traffic Analysis, and Anomaly Center views that share the current analysis. It uses only the Python standard library. The live sensor extracts packet and flow metadata; it does not save packet payloads or PCAP files.

## Run locally

Requires Python 3.10 or newer.

```sh
python3 app.py --port 8000
```

Open <http://127.0.0.1:8000>. This runs the dashboard, sample data, and CSV analysis on the same port used by the systemd service. If the service is already running, stop it before launching the app directly:

```sh
sudo systemctl stop strata
```

Stop the directly launched server with `Ctrl+C`. Start the service again with `sudo systemctl start strata` when finished.

For live packet capture, install and run the restricted systemd service below. It runs as the dedicated `strata` account with only `CAP_NET_RAW`; do not run the web application as root.

### Confirm live capture is working

After starting capture, the dashboard should show **Monitoring** followed by the selected interface name. The packet and active-flow counters should increase while the computer is using the network. You can also check the local API:

```sh
curl http://127.0.0.1:8000/api/live/interfaces
curl http://127.0.0.1:8000/api/live/status
```

The first endpoint should return an interface list. While capture is running, the status response should contain `"state": "running"` and increasing `packets_seen` and `active_flows` values. A running capture may have no active flows during an idle period.

The dashboard is deliberately bound to loopback. It checks the browser `Host` and `Origin` headers and must not be exposed on a LAN or the public internet. The live-capture start operation requires Linux `CAP_NET_RAW`; without it, CSV analysis and the dashboard remain usable, but live capture will return an explanatory error. Do not run the whole web server as root to work around this.

### Troubleshooting

- **Interface discovery fails or the list is empty:** confirm you opened the dashboard from the same running Strata server at `http://127.0.0.1:8000`, then check `/api/live/interfaces`. The service discovers interfaces from Linux `/sys/class/net` and lists active non-loopback interfaces.
- **Capture fails to start:** live capture needs Linux and `CAP_NET_RAW`. For systemd, use the restricted service unit below; do not run the web server as root.
- **Capture is running but counters stay at zero:** generate traffic from this computer and confirm the selected interface is the one carrying it. Capture only sees traffic delivered to that interface.
- **No other Wi-Fi clients appear:** this is expected. Strata does not use monitor mode or collect traffic from other stations; see [What live capture can see](#what-live-capture-can-see).

## Run with a restricted systemd service

For a persistent local installation, copy this project to `/opt/strata`, create a dedicated unprivileged `strata` account, and install `systemd/strata.service` as `/etc/systemd/system/strata.service`. The unit binds the UI to loopback and grants the service only `CAP_NET_RAW` for the packet socket:

```sh
getent passwd strata >/dev/null || sudo useradd --system --no-create-home --shell /usr/sbin/nologin strata
sudo install -d -o root -g root -m 0755 /opt/strata
sudo cp -a . /opt/strata/
sudo chown -R root:root /opt/strata
sudo chmod -R a+rX /opt/strata
sudo install -m 0644 systemd/strata.service /etc/systemd/system/strata.service
sudo systemctl daemon-reload
sudo systemctl enable --now strata
```

Open <http://127.0.0.1:8000>. Manage the service with:

```sh
sudo systemctl status strata --no-pager
sudo systemctl restart strata
sudo journalctl -u strata -n 50 --no-pager
sudo systemctl stop strata
```

Review the unit and your local systemd policy before installation. Do not add a broad capability to a shared Python interpreter.

### Migrate an existing NetSentry installation

If the older `netsentry` service is installed, install and verify Strata before removing its old unit. The services use the same local port, so stop the old service before starting Strata. If Strata does not start, restore the old service with `sudo systemctl start netsentry` and inspect `sudo journalctl -u strata -n 50 --no-pager`.

From the Strata project directory:

```sh
getent passwd strata >/dev/null || sudo useradd --system --no-create-home --shell /usr/sbin/nologin strata
sudo systemctl stop netsentry
sudo install -d -o root -g root -m 0755 /opt/strata
sudo cp -a . /opt/strata/
sudo chown -R root:root /opt/strata
sudo chmod -R a+rX /opt/strata
sudo install -m 0644 systemd/strata.service /etc/systemd/system/strata.service
sudo systemctl daemon-reload
sudo systemctl enable --now strata
```

Confirm that `systemctl status strata` reports active and that <http://127.0.0.1:8000/api/health> responds successfully. Then remove the old service unit:

```sh
sudo systemctl disable netsentry
sudo rm /etc/systemd/system/netsentry.service
sudo systemctl daemon-reload
```

The migration leaves `/opt/netsentry` and the old `netsentry` system account in place; remove them separately only after confirming nothing else uses them.

### Does live capture work over Ethernet?

Yes. On Linux, select the active wired interface in the dashboard (often named `eth0`, `enp…`, or similar) and start monitoring. Ethernet uses the same `CAP_NET_RAW` permission as Wi-Fi capture. Strata analyzes traffic visible to this computer on that interface; connecting by Ethernet does not make it a monitor for every device on the network.

## What live capture can see

On Linux, live capture listens to the selected interface in its normal host mode. It can analyze traffic visible to this machine, including its own Wi-Fi/Ethernet traffic. It does **not** put Wi-Fi into monitor mode, decrypt other stations' traffic, discover every device on the access point, or inspect traffic that the host/network does not deliver to that interface. Monitoring other clients requires an authorized router/firewall flow export or switch/AP mirror feed; this app does not configure those network devices.

Each observation is decoded in memory into IP endpoints, transport ports/protocol, TCP flags, packet/byte counters, and flow duration. Non-IP frames, malformed packets, and fragmented traffic that cannot be decoded are ignored for flow analysis. Payload bytes are not logged or persisted. Active flow state is capped in memory and expires after 90 seconds idle; the dashboard keeps a bounded recent-flow window. Stopping the service clears all capture data.

## CSV flow import

CSV must have a header row and one flow record per row. For example:

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration_ms,total_packets,total_bytes
2026-10-05T10:00:00Z,10.0.0.4,172.16.0.12,51234,443,TCP,120,34,18000
```

Numeric columns present in at least 60% of rows become selectable statistical features. The API accepts up to 10,000 records, 100 columns, 512 characters per field, and 5 MB per request.

## Detection and limitations

Numeric features use a median/MAD robust outlier score (with an IQR fallback); port numbers are treated categorically. Explainable heuristics cover selected unusual destination ports, extreme packet/byte volumes, average packet size, and selected TCP flags. Sensitivity is configurable; the UI provides live search, severity filters, anomaly charting, and CSV export.

This is a useful local monitoring and triage baseline, **not a guarantee of detecting every threat or a certified production NDR/IDS**. False positives and missed attacks are possible, especially with encrypted traffic, unsupported frame types, short baselines, or incomplete visibility. It does not block traffic, alert externally, persist an audit history, or support multi-user access. Keep it local; a remote deployment needs a separately secured, authenticated TLS front end and an authorized network telemetry source.

## Free public demo

The Render blueprint in [`render.yaml`](render.yaml) configures a free-tier, public demo using the separate [`demo_server.py`](demo_server.py) entry point. The hosted version uses synthetic sample traffic only: live-capture endpoints and CSV imports are disabled, and visitor-provided flow records are never analyzed. Render free web services can spin down when idle, so the first visit after inactivity may take a little time to load.

To deploy it, sign in to [Render](https://render.com), authorize access to this private GitHub repository, and create a Blueprint from `Avaqen/Strata`. Render reads `render.yaml` and provisions the service. Add the resulting `onrender.com` URL here once deployment is complete. A Render account and permission to connect this repository are required; no API keys or application secrets are needed.

[Open Render to deploy the free demo](https://render.com/deploy?repo=https://github.com/Avaqen/Strata)

## Test

Run the unit tests from the project directory:

```sh
python3 -m unittest discover -s tests -v
```
