# Feature extraction

Turns the pcaps listed in a manifest into one row of session-level traffic features per pcap.
`FEATURE_SPEC.md` in the repo root defines every feature; this file covers usage and caveats.

## Run

```terminal
python3 processing/pre-process.py extract --manifest manifest.csv --out output
python3 processing/pre-process.py extract --manifest manifest.csv --out output \
    --config processing/config.yaml --burst-thresholds 1 5 --min-think-time 0.05 --reuse-cache
```

Relative `pcap_path` values resolve against the manifest's directory. CLI flags override the YAML
config. `--reuse-cache` reads the cached packet tables instead of re-parsing pcaps whose path,
mtime and manifest IPs are unchanged, which is all a new feature needs.

Tests: `cd processing && python3 -m pytest`.

## Outputs (`--out`)

| path | content |
|---|---|
| `features.csv` | manifest columns, the 41 features, then `diag_*` columns (not features) |
| `cache/<run_id>.packets.parquet` | filtered per-packet table (§3.2) |
| `cache/<run_id>.turns.csv` | every think-time turn; `kept` marks those passing the §4.7 filters |
| `cache/<run_id>.meta.json` | attacker/victim, raw packet count, parse warnings |
| `run.log` | files processed, warnings, failures |

A pcap that fails gets a row with NaN features and `ERROR: …` in `diag_warnings`; the batch goes on.

For modelling, select columns via `extraction.columns.FEATURE_GROUPS` (`rates`, `ratios`,
`duration`, `iat`, `burstiness`, `bursts_t1s`, `bursts_t5s`, `think`) or `FEATURE_COLUMNS`.
Never feed `diag_*` columns to a model.

## Layout

- `extraction/parse.py`: pcap/pcapng → per-packet table. Ethernet (incl. VLAN), Linux SLL/SLL2, raw IPv4.
- `extraction/features/`: one module per feature group, each a pure function over the table.
- `extraction/columns.py`: column names and groups. `extraction/cli.py`: batch run.

## Caveats

From the spec (§8), not corrected in the features:

- **Interactive echo:** with character-mode protocols (telnet), each keystroke gets a small echo,
  so turns measure typing rhythm. Study with `--min-response-bytes`.
- **Automatic protocol responses:** banners make client software answer within milliseconds, giving
  near-zero think times unrelated to the actor. Several runs have a sub-millisecond `think_median`,
  so this is real in this dataset. Study with `--min-think-time`.
- **Concurrent connections** are merged into one stream; a turn can pair a response on one
  connection with a request on another.
- **Capture point:** all pcaps must be captured at the same point (victim side), or small-scale
  timing such as `iat_all_min` differs between classes for reasons unrelated to the actor.

From the implementation:

- **Timestamp precision:** `ts` is float64 epoch seconds, which resolves ~0.2 µs at current epoch
  values. Finer (nanosecond pcap) precision is lost; microsecond pcaps are unaffected in practice.
- **Attacker inference** (only when the manifest has no IPs) takes the first SYN in file order,
  which is time order for tcpdump captures.
- **TCP header not captured:** if the snaplen cuts the TCP header before the data offset field,
  `payload_len` is set to 0 and a warning is recorded. Snaplen 96 on Ethernet always captures it.
- **IP fragments:** non-first fragments count their whole IP payload as `payload_len` and have no
  ports or TCP fields, so they are never treated as retransmissions.
