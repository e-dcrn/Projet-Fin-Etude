"""Pause de l'agent bénin de la source pendant un scénario (vérité terrain de la détection)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from app.traffic import TrafficManager, WORDLIST, LAB_PASSWORD

P = "idslab"


def _helper(status="running", node="pc-1", **labels):
    return SimpleNamespace(
        status=status, attrs={"Config": {"Cmd": ["python3", "agent"]}},
        labels={f"{P}.attached": node, **{f"{P}.{k}": v for k, v in labels.items()}}, remove=MagicMock(),
    )


def _manager(traffic=(), scenarios=()):
    lab = MagicMock()
    lab.settings.prefix = P
    lab.helpers.side_effect = lambda role: {"traffic": list(traffic), "scenario": list(scenarios)}[role]
    lab.find_device.return_value = SimpleNamespace(status="running", id="c")
    return TrafficManager(lab), lab


def test_source_agent_is_paused_then_resumed_with_same_command():
    agent = _helper(profile="intense", dest="all")
    manager, lab = _manager(traffic=[agent])
    manager._pause_benign("pc-1")
    agent.remove.assert_called_once()
    manager._resume_benign("pc-1")
    args, kwargs = lab.start_netns_helper.call_args
    assert args[2] == ["python3", "agent"] and kwargs["role"] == "traffic" and kwargs["profile"] == "intense"
    assert "pc-1" not in manager._paused


def test_other_equipment_agent_is_left_alone():
    agent = _helper(node="pc-2")
    manager, _ = _manager(traffic=[agent])
    manager._pause_benign("pc-1")
    agent.remove.assert_not_called()


def test_agent_waits_for_the_last_attack_of_the_source():
    manager, lab = _manager(scenarios=[_helper()])
    manager._paused["pc-1"] = {"command": ["x"], "profile": "", "dest": ""}
    manager._resume_benign("pc-1")
    lab.start_netns_helper.assert_not_called()


def test_wordlist_ends_with_the_real_password():
    assert len(WORDLIST) > 50 and WORDLIST[-1] == LAB_PASSWORD


def test_wait_until_finished_follows_the_real_end_of_the_attack():
    helper = MagicMock(status="running")
    states = iter(["running", "exited"])
    helper.reload.side_effect = lambda: setattr(helper, "status", next(states))
    TrafficManager._wait_until_finished(helper)
    assert helper.status == "exited" and helper.reload.call_count == 2
