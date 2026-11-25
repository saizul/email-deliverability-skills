import csv
import io
import json
from datetime import date

import pytest

from conftest import load_script, run_script

SKILL = "warmup-plan"
SCRIPT = "warmup_plan.py"
mod = load_script(SKILL, SCRIPT)


def test_plan_reaches_target_and_holds():
    plan = mod.build_plan(50000, start=50, growth=1.5, start_date=date(2026, 12, 1))
    vols = [d["volume"] for d in plan]
    assert vols[0] == 50 and vols[-3:] == [50000] * 3
    assert all(b >= a for a, b in zip(vols, vols[1:]))
    assert all(b / a <= 1.6 for a, b in zip(vols, vols[1:]))
    assert plan[0]["date"] == "2026-12-01" and plan[1]["date"] == "2026-12-02"
    assert plan[0]["segment"].startswith("engaged 30") and plan[-1]["segment"].startswith("full")
    assert plan[-1]["cumulative"] == sum(vols)
    assert len(plan) == 21


def test_presets_change_length():
    lengths = {k: len(mod.build_plan(100000, growth=g)) for k, g in mod.PRESETS.items()}
    assert lengths["conservative"] > lengths["standard"] > lengths["aggressive"]


def test_weekdays_only_and_providers():
    share = {"gmail": 0.5, "other": 0.5}
    plan = mod.build_plan(1000, start=100, growth=2.0, start_date=date(2026, 12, 4), share=share, weekdays_only=True)
    days = [date.fromisoformat(d["date"]).weekday() for d in plan]
    assert all(wd < 5 for wd in days)
    assert plan[1]["date"] == "2026-12-07"  # Friday -> Monday
    assert plan[0]["providers"] == {"gmail": 50, "other": 50}


def test_start_above_target_and_validation():
    plan = mod.build_plan(30, start=50)
    assert plan[0]["volume"] == 30
    with pytest.raises(ValueError):
        mod.build_plan(1000, growth=1.0)
    with pytest.raises(ValueError):
        mod.build_plan(0)


@pytest.mark.parametrize(
    "metrics,decision",
    [
        ({"bounce": 0.5, "complaint": 0.02, "deferral": 1}, "advance"),
        ({"bounce": 2.5}, "hold"),
        ({"complaint": 0.15}, "hold"),
        ({"deferral": 6}, "hold"),
        ({"bounce": 6}, "step back"),
        ({"complaint": 0.3}, "step back"),
        ({"blocks": 1}, "step back"),
        ({"deferral": 20}, "step back"),
    ],
)
def test_decide(metrics, decision):
    assert mod.decide(metrics)["decision"] == decision


def test_cli_outputs():
    r = run_script(SKILL, SCRIPT, "--target", "5000", "--start-date", "2026-12-01", "--providers")
    assert (
        r.returncode == 0
        and "| Day | Date |" in r.stdout
        and "gmail" in r.stdout
        and "Advance to the next row" in r.stdout
    )
    r = run_script(SKILL, SCRIPT, "--target", "5000", "--preset", "conservative", "--json")
    data = json.loads(r.stdout)
    assert data["growth"] == 1.3 and data["days"][-1]["volume"] == 5000
    r = run_script(SKILL, SCRIPT, "--target", "2000", "--growth", "2", "--csv", "--providers", "gmail=0.6,other=0.4")
    rows = list(csv.DictReader(io.StringIO(r.stdout)))
    assert rows[0]["volume"] == "50" and rows[0]["gmail"] == "30"


def test_cli_metrics_and_errors():
    r = run_script(SKILL, SCRIPT, "--metrics", "bounce=0.4,complaint=0.01")
    assert r.returncode == 0 and "ADVANCE" in r.stdout
    r = run_script(SKILL, SCRIPT, "--metrics", "bounce=3%", "--json")
    assert r.returncode == 1 and json.loads(r.stdout)["decision"] == "hold"
    assert run_script(SKILL, SCRIPT, "--metrics", "bounce").returncode == 2
    assert run_script(SKILL, SCRIPT).returncode == 2
    assert run_script(SKILL, SCRIPT, "--target", "100", "--providers", "gmail=0.5").returncode == 2
    assert run_script(SKILL, SCRIPT, "--target", "100", "--start-date", "tomorrow").returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
