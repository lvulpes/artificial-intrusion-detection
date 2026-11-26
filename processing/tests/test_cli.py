"""§6 batch run: output layout, column order, failures recorded without aborting, cache reuse."""

import math

import pandas as pd
import pytest

from extraction.cli import main, read_manifest
from extraction.columns import DIAG_COLUMNS, FEATURE_COLUMNS

from . import pcaps
from .pcaps import ATTACKER, VICTIM, WORKED_EXAMPLE


@pytest.fixture
def manifest(tmp_path):
    (tmp_path / "pcaps").mkdir()
    pcaps.write_pcap(tmp_path / "pcaps" / "good.pcap", pcaps.frames(WORKED_EXAMPLE))
    pcaps.write_pcap(tmp_path / "pcaps" / "noips.pcap", pcaps.frames(WORKED_EXAMPLE))
    (tmp_path / "pcaps" / "garbage.pcap").write_bytes(b"not a pcap at all")
    rows = [
        ["pcaps/good.pcap", "ai", "run-1", ATTACKER, VICTIM, "vsftpd"],
        ["pcaps/missing.pcap", "human", "run-2", ATTACKER, VICTIM, "samba"],
        ["pcaps/garbage.pcap", "human", "run-3", ATTACKER, VICTIM, "samba"],
        ["pcaps/noips.pcap", "human", "run-4", "", "", "unreal"],
    ]
    path = tmp_path / "manifest.csv"
    pd.DataFrame(rows, columns=["pcap_path", "label", "run_id", "attacker_ip", "victim_ip", "challenge"]).to_csv(
        path, index=False)
    return path


def test_batch(manifest, tmp_path):
    out = tmp_path / "out"
    assert main(["extract", "--manifest", str(manifest), "--out", str(out)]) == 0

    df = pd.read_csv(out / "features.csv", keep_default_na=False, na_values=[""])
    manifest_cols = ["pcap_path", "label", "run_id", "attacker_ip", "victim_ip", "challenge"]
    assert list(df.columns) == manifest_cols + FEATURE_COLUMNS + DIAG_COLUMNS
    assert df["run_id"].tolist() == ["run-1", "run-2", "run-3", "run-4"]
    assert df["challenge"].tolist() == ["vsftpd", "samba", "samba", "unreal"]

    good = df.iloc[0]
    assert good["duration_s"] == pytest.approx(10.2)
    assert good["diag_n_packets_raw"] == 11 and good["diag_n_turns"] == 2
    assert good["diag_ip_inferred"] in (False, "False")

    for i in (1, 2):
        assert df.iloc[i]["diag_warnings"].startswith("ERROR:")
        assert math.isnan(df.iloc[i]["duration_s"])

    inferred = df.iloc[3]
    assert inferred["diag_ip_inferred"] in (True, "True")
    assert inferred["diag_attacker_ip"] == ATTACKER
    assert "inferred" in inferred["diag_warnings"]

    cache = out / "cache"
    assert (cache / "run-1.packets.parquet").exists()
    assert pd.read_csv(cache / "run-1.turns.csv").columns.tolist() == ["ts", "think_time", "response_bytes", "kept"]
    log = (out / "run.log").read_text()
    assert "2 failed" in log and "run-2" in log and "run-3" in log


def test_reuse_cache_gives_same_output(manifest, tmp_path):
    out = tmp_path / "out"
    main(["extract", "--manifest", str(manifest), "--out", str(out)])
    first = (out / "features.csv").read_text()
    main(["extract", "--manifest", str(manifest), "--out", str(out), "--reuse-cache"])
    assert (out / "features.csv").read_text() == first
    assert "using cached packet table" in (out / "run.log").read_text()


def test_config_flags_change_thresholds(manifest, tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("burst_thresholds_s: [2]\nmin_think_time_s: 5\n")
    out = tmp_path / "out"
    main(["extract", "--manifest", str(manifest), "--out", str(out), "--config", str(cfg),
          "--burst-thresholds", "0.5", "10"])
    df = pd.read_csv(out / "features.csv")
    assert "n_bursts_t0.5s" in df.columns and "n_bursts_t10s" in df.columns
    assert "n_bursts_t2s" not in df.columns
    assert df.iloc[0]["diag_n_turns"] == 1  # only the 7 s turn passes min_think_time_s=5


@pytest.mark.parametrize("bad, message", [
    ("pcap_path,label\nx.pcap,ai\n", "missing required columns"),
    ("pcap_path,label,run_id\nx.pcap,robot,r1\n", "labels"),
    ("pcap_path,label,run_id\nx.pcap,ai,r1\ny.pcap,ai,r1\n", "duplicate run_id"),
])
def test_manifest_validation(tmp_path, bad, message):
    path = tmp_path / "m.csv"
    path.write_text(bad)
    with pytest.raises(ValueError, match=message):
        read_manifest(path)
