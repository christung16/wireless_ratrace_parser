# Cisco C9800 Wireless Onboarding Parser

`parse_onboarding.py` analyzes output from `show logging profile wireless start`.
It reports client onboarding results for one SSID by AP and hardware platform.
The platform is obtained by joining each AP to a Catalyst Center inventory CSV.

## Requirements

- Python 3.10 or newer
- `openpyxl` for optional XLSX export (installed in the project virtual environment)
- A C9800 wireless profile log
- An inventory CSV containing `Device Name`, `MAC Address`, and `Platform`

Install the Python dependency in the project virtual environment:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

## Run

The default SSID is `Corp@company`, and the default inventory file is
`test_inventory_2f.csv`:

```bash
.venv/bin/python parse_onboarding.py 11sep-wlc.log
```

The values can be supplied explicitly:

```bash
.venv/bin/python parse_onboarding.py \
  --ssid Corp@company \
  --inventory test_inventory_2f.csv \
  11sep-wlc.log
```

Before generating a report, `parse_onboarding.py` extracts the selected SSID's
BSSIDs from the log and previews every changed inventory AP. If changes exist,
it prompts before updating the inventory in place. Answering `yes` creates a
timestamped `.bak` copy beside the inventory and writes the update atomically;
declining continues the report with the existing inventory. Multiple BSSIDs for
one AP are stored as semicolon-separated values.

The mapping can also be run separately:

```bash
.venv/bin/python map_bssid.py 11sep-wlc.log test_inventory_2f.csv
```

Use `--output PATH` with `map_bssid.py` to write a separate CSV without a
confirmation prompt or inventory backup. APs without an association record for
the selected SSID have a blank value.

Client MAC address lists are hidden by default. Show them in the failure report
with:

```bash
.venv/bin/python parse_onboarding.py --show-macs 11sep-wlc.log
```

The console report summarizes MAB and DOT1X AAA transactions. MAB latency is
measured from `MAB Authentication initiated` to `MAB Authentication success`.
DOT1X latency is measured from `L2 Authentication initiated. method DOT1X` to
`L2 Authentication Key Exchange Start`, which indicates that EAP/AAA completed.
Both use the trace's sub-second timestamps. A transaction without a completion
record is marked incomplete; its client deletion reason is reported when
present, otherwise the reason indicates that no completion appeared before the
end of the capture. Fast roams that do not perform a new AAA exchange are not
counted as AAA transactions.

The XLSX `Per AP` worksheet reports attempts, successes, and success rates
separately for association and reassociation, followed by the unchanged total
attempts and successes. A rate is blank when that AP has no attempts of the
corresponding type. The worksheet also includes selected-SSID average AAA
latency and incomplete transaction count. `AAA by Client` includes completion
and latency metrics plus each AP's transaction count for every observed client.
When incomplete transactions exist, `AAA Incomplete` lists their client MAC,
AP, timestamps, and reason. With `--client-logs`, stdout also prints AAA metrics
for the requested client MAC addresses.

Show a specified number of client MACs with the most failure events on each
hardware platform, together with each client's failure reasons and counts:

```bash
.venv/bin/python parse_onboarding.py --top-error-clients 5 11sep-wlc.log
```

This report intentionally displays the ranked client MACs even when
`--show-macs` is not supplied. The number must be greater than zero. If it is
larger than the number of failing clients on a platform, all failing clients on
that platform are listed.

Create detail trace worksheets for the first ranked clients on each platform:

```bash
.venv/bin/python parse_onboarding.py \
  --top-error-clients 10 \
  --top-error-client-logs 3 \
  --xlsx top-error-client-logs.xlsx \
  11sep-wlc.log
```

`--top-error-client-logs N` selects the first `N` clients per platform from
`Top Error Clients` and creates the same `Client <MAC>` worksheets as
`--client-logs`. It requires `--top-error-clients` and `--xlsx`, and its value
must be greater than zero and no larger than `--top-error-clients`. A client
ranked on multiple platforms receives one detail worksheet. Explicit
`--client-logs` MACs are merged with the ranked clients without duplicates.

Write every log record for one or more clients to separate XLSX worksheets:

```bash
.venv/bin/python parse_onboarding.py \
  --client-logs 6677.8899.aabb,0011.2233.4455 \
  --client-logs aa-bb-cc-dd-ee-ff \
  --xlsx client-logs.xlsx \
  11sep-wlc.log
```

The MAC may use dotted, colon-separated, hyphen-separated, or plain hexadecimal
notation. Supply comma-separated MACs or repeat `--client-logs`; duplicates are
removed. Existing `--start-time` and `--end-time` boundaries also apply. Raw
client traces are not printed to stdout. Each requested MAC gets its own XLSX
worksheet named `Client <MAC>`, and failure rows use bold red font. For failure
events, each row identifies the failure reason and explains in `Counted
Onboarding Failure` why it was counted or excluded. This field is blank for
non-failure events. Because client traces are XLSX-only, `--client-logs`
requires `--xlsx`.

Save the same report to an XLSX workbook in addition to stdout:

```bash
.venv/bin/python parse_onboarding.py \
  --xlsx onboarding-report.xlsx \
  11sep-wlc.log
```

Add `--show-macs` to include affected client MAC address lists in the XLSX
`Failure Reasons` sheet. AP MAC identifiers and distinct client MAC counts are
always included.

Limit the report to an inclusive HKT time range:

```bash
.venv/bin/python parse_onboarding.py \
  --start-time "2026-09-11 09:00:00" \
  --end-time "2026-09-11 12:00:00" \
  --xlsx onboarding-0900-1200.xlsx \
  11sep-wlc.log
```

Either boundary can be used by itself. ISO timestamps with a `T` separator are
also accepted. Do not include a UTC offset; the controller timestamps are
interpreted as HKT.

## Classification Logic

### Attempt

An attempt starts when the log contains `Association received.` or
`Re-Association received.` and the `WLAN` value exactly matches the requested
SSID. Its BSSID must also map to the same AP in the inventory's `<SSID> BSSID`
column. The same record supplies the client MAC, AP MAC, and AP name.

Every matching association record is counted as one attempt. Repeated attempts
by the same client therefore increase the attempt count, while the distinct
client MAC count increases only once.

When a time range is supplied, an attempt is included only when its association
record occurs inside the inclusive range. A success or failure is counted only
if its terminal event also occurs before the end boundary. Otherwise, that
attempt remains unresolved in the selected range.

### Success

An active attempt succeeds when that client reaches this state transition:

```text
S_CO_<state> -> S_CO_RUN
```

The success is assigned to the AP from the client's matching association
record. Success rate is calculated as:

```text
success rate = successful attempts / all attempts * 100
```

### Failure

An active attempt can fail when `Client delete initiated. Reason:` occurs before
the client reaches `S_CO_RUN`. The parser defers the decision until the related
`Send delete mobile` record supplies the deletion BSSID. A failure is counted
only when that BSSID matches the inventory's `<SSID> BSSID` value for the same
AP as the active attempt. This excludes teardown events for a previous AP or
another WLAN during roaming and WLAN changes.

A deletion for another BSSID does not terminate the active attempt. The parser
continues tracking that attempt, so a later `S_CO_RUN` transition is counted as
a success and a later matching deletion can still be counted as its failure.

If the trace does not emit a deletion BSSID, the parser falls back to the active
attempt established by the association record. A deletion with a mapped Corp
BSSID is still excluded when no onboarding attempt is active, such as after the
client has already reached `S_CO_RUN`. The deletion reason is recorded as the
failure reason. Reasons containing `SUCCESS` are not classified as failures.

Multiple error messages during one attempt do not create multiple failures.
Only the terminal client deletion is counted, once, for that attempt.

### Unresolved Attempts

An attempt is unresolved when the capture ends, or another association replaces
it, before either a successful `S_CO_RUN` transition or a terminal failure is
seen. Unresolved attempts remain in the attempt denominator but are not counted
as successes or failures. Consequently, successes plus failures can be less
than attempts.

## AP And Platform Mapping

The AP name and controller MAC come directly from the association record. The
parser joins the controller MAC to the inventory CSV `MAC Address`, normalizing
Cisco dotted and colon-separated formats. It falls back to `Device Name` when a
MAC match is unavailable. Unmatched APs are grouped under `Not in inventory`.

Per-platform totals are sums of the per-AP event counts. Client MAC totals are
distinct sets, so a client roaming between APs of the same platform is counted
once for that platform. In `By Platform`, `Association Rate all SSID (per AP)`
shows the average number of association and reassociation events across all
SSIDs per inventory AP device on that platform. `Attempts` remains limited to
the selected SSID, while `Association Events` includes every SSID in the
selected time range:

```text
Association Rate all SSID (per AP) = all-SSID association events / inventory AP devices
```

## Output

The report contains:

1. Capture start and stop times in HKT.
2. Per-AP attempts, successes, failures, success rate, and distinct client MACs.
3. The same metrics aggregated by platform, including all-SSID association
  events and association events per inventory AP device.
4. Failure reasons per platform, including failure-event count, distinct client
  count, and optionally the affected client MAC addresses.
5. Optionally, the top failing client MACs per platform and their failure
   reasons when `--top-error-clients` is supplied.
6. Optionally, separate XLSX worksheets containing all matching records for
  each client supplied with `--client-logs` or selected with
  `--top-error-client-logs`.

With `--xlsx`, the workbook contains `Summary`, `Per AP`, `By Platform`, and
`Failure Reasons` sheets. When requested, it also contains a `Top Error Clients`
sheet and/or one `Client <MAC>` sheet per requested client. Client traces are
excluded from stdout. The XLSX file is written in addition to the stdout report.

The C9800 records do not include a UTC offset. The parser treats the displayed
controller timestamps as HKT (`UTC+08:00`); it does not shift the clock values.
