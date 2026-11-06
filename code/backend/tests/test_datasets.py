"""Tests de l'étiquetage par fenêtres d'attaque et du stockage des datasets (app/datasets.py)."""

import csv
import io

import pytest

from app.cicflowmeter import parse_timestamp
from app.datasets import AttackRun, DatasetError, DatasetStore, label_dataset_csv

# 2026-10-30 10:00:00 UTC
T0 = 1793354400.0


def _run(needs="ip", target="10.0.1.10", start=T0, end=T0 + 20, subcategory="port-scan"):
    return AttackRun(
        attack="tcp-connect-scan", name="Scan", category="reconnaissance", subcategory=subcategory,
        needs=needs, source="pc-1", source_name="PC-1", source_ip="10.0.1.2", target=target,
        speed="fast", start=start, end=end,
    )


def _csv(rows):
    lines = ["Flow ID,Src IP,Dst IP,Timestamp,Label"]
    lines += [f"f{i},{src},{dst},{ts},NeedManualLabel" for i, (src, dst, ts) in enumerate(rows)]
    return "\n".join(lines) + "\n"


def _labels(csv_text):
    return [row["Label"] for row in csv.DictReader(io.StringIO(csv_text))]


def test_parse_cicflowmeter_timestamp():
    assert parse_timestamp("2026-10-30 10:00:00.500000") == T0 + 0.5
    assert parse_timestamp("2026-10-30 10:00:00") == T0
    assert parse_timestamp("n/a") is None


def test_label_by_source_target_and_window():
    rows = [
        ("10.0.1.2", "10.0.1.10", "2026-10-30 10:00:05.000000"),  # pendant l'attaque : attaque
        ("10.0.1.2", "10.0.1.10", "2026-10-30 09:59:00.000000"),  # avant la fenêtre : bénin
        ("10.0.1.2", "10.0.1.10", "2026-10-30 10:01:00.000000"),  # après la fenêtre : bénin
        ("10.0.1.3", "10.0.1.10", "2026-10-30 10:00:05.000000"),  # autre source : bénin
        ("10.0.1.2", "10.0.1.11", "2026-10-30 10:00:05.000000"),  # autre cible : bénin
    ]
    text, counts, total = label_dataset_csv(_csv(rows), [_run()])
    assert _labels(text) == ["port-scan", "BENIGN", "BENIGN", "BENIGN", "BENIGN"]
    assert counts == {"port-scan": 1, "BENIGN": 4}
    assert total == 5


def test_label_subnet_attack_and_epoch_timestamps():
    # Exporteur interne : Timestamp en secondes epoch ; balayage d'un sous-réseau.
    rows = [
        ("10.0.1.2", "10.0.1.50", str(T0 + 3)),
        ("10.0.1.2", "10.0.2.50", str(T0 + 3)),
    ]
    run = _run(needs="subnet", target="10.0.1.0/24", subcategory="ping-sweep")
    text, counts, _ = label_dataset_csv(_csv(rows), [run])
    assert _labels(text) == ["ping-sweep", "BENIGN"]


def test_label_several_attacks_by_window():
    rows = [
        ("10.0.1.2", "10.0.1.10", "2026-10-30 10:00:05.000000"),
        ("10.0.1.2", "10.0.1.10", "2026-10-30 10:00:45.000000"),
    ]
    runs = [_run(), _run(start=T0 + 40, end=T0 + 50, subcategory="ssh-patator")]
    text, _, _ = label_dataset_csv(_csv(rows), runs)
    assert _labels(text) == ["port-scan", "ssh-patator"]


def test_store_roundtrip(tmp_path):
    store = DatasetStore(tmp_path)
    dataset_id = store.new_id()
    store.save(dataset_id, {"id": dataset_id, "name": "essai"}, {"flows.csv": "a,b\n", "capture.pcap": b"\xd4\xc3\xb2\xa1"})
    assert store.get(dataset_id)["name"] == "essai"
    assert [m["id"] for m in store.list()] == [dataset_id]
    assert store.file_path(dataset_id, "flows.csv").read_text() == "a,b\n"
    # Deux datasets créés dans la même seconde ont des identifiants distincts.
    assert store.new_id() != dataset_id
    store.delete(dataset_id)
    assert store.list() == []


def test_store_rejects_unsafe_ids_and_files(tmp_path):
    store = DatasetStore(tmp_path)
    with pytest.raises(DatasetError):
        store.get("../etc")
    dataset_id = store.new_id()
    store.save(dataset_id, {"id": dataset_id}, {})
    with pytest.raises(DatasetError):
        store.file_path(dataset_id, "../../secret")


def _plan(variants=2):
    from app.datasets import DatasetPlan
    attackers = [{"node": f"pc-{i}", "name": f"PC-{i}", "ip": f"10.0.1.1{i}"} for i in (1, 2, 3)]
    attackers.append({"node": "server-1", "name": "Serveur-Web", "ip": "10.0.1.10"})
    runs = [
        _run(),  # PC-1 (10.0.1.2) → 10.0.1.10, rapide
        _run(subcategory="service-detection"),
    ]
    runs[1].speed = "normal"
    return DatasetPlan(
        name="Programme", probe="ids-1", probe_name="IDS-1", probe_ip="", kinds=["http"], profile="intense",
        benign=[], runs=runs, warmup=10, gap=5, cooldown=10, max_attack=30, variants=variants, attackers=attackers,
    )


def test_variant_changes_sources_speeds_and_benign_profile():
    from app.datasets import make_variant
    plan = _plan()
    variant = make_variant(plan, 1)
    for original, changed in zip(plan.runs, variant.runs):
        assert changed.source != original.source           # autre machine d'attaque
        assert changed.source_ip != original.target         # jamais la cible elle-même
        assert changed.speed != original.speed              # autre vitesse
        assert (changed.target, changed.attack) == (original.target, original.attack)
        assert changed.start is None and changed.end is None
    assert variant.profile != plan.profile
    assert variant.variants == 0 and variant.group["role"] == "variant" and variant.group["index"] == 1
    assert variant.name == "Programme — variante 1"
    assert len(variant.group["changes"]) == len(plan.runs) + 1
    # Le programme d'origine n'est pas modifié, et deux variantes diffèrent entre elles.
    assert plan.runs[0].source == "pc-1" and plan.profile == "intense"
    assert [r.source for r in make_variant(plan, 2).runs] != [r.source for r in variant.runs]
    # Déterministe
    assert [(r.source, r.speed) for r in make_variant(plan, 1).runs] == [(r.source, r.speed) for r in variant.runs]
