"""
Génération d'un dataset étiqueté sur le réseau instancié (« façon ConCap »).

Un dataset est produit par une tâche de fond (voir jobs.py) qui joue un
programme complet sur la topologie déployée :

  1. la SONDE IDS capture le trafic du segment qu'elle surveille (copie de tout
     le trafic du switch, comme la détection en direct) : c'est le seul point de
     capture possible, une topologie sans Sonde IDS ne permet pas de dataset ;
  2. des agents de trafic bénin tournent pendant toute la durée ;
  3. les attaques du programme s'enchaînent (une à la fois, entrecoupées de
     trafic bénin seul), chacune dans une fenêtre de temps enregistrée ;
  4. le pcap est converti en flux CICFlowMeter (repli : exporteur interne) ;
  5. chaque flux est étiqueté : il est « attaque » s'il va de la source vers la
     cible d'une attaque ET commence pendant la fenêtre de cette attaque,
     « BENIGN » sinon. Pendant son attaque, la source ne fait pas de trafic
     bénin (son agent est mis en pause), ce qui rend la règle exacte.

Le résultat est sauvegardé sur disque (data/datasets/<id>/ : flows.csv,
capture.pcap, meta.json) : il survit à l'arrêt du réseau et reste traçable
(paramètres, fenêtres d'attaque, décompte des étiquettes).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Dict, List, Optional

from docker.errors import DockerException

from .cicflowmeter import FLOW_WINDOW_SEC, parse_timestamp, relabel_csv, windowed_flows_csv
from .flows import build_flows, flows_to_csv, parse_pcap, split_pcap
from .jobs import Job
from .settings import BACKEND_DIR
from .store import RecordStore
from .traffic import ATTACKS, BENIGN_PROFILES, SPEEDS, TARGET_RE, TrafficError, TrafficManager

log = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("IDSLAB_DATA_DIR", BACKEND_DIR / "data")) / "datasets"

# Fichiers d'un dataset téléchargeables depuis l'interface → type MIME.
FILES = {
    "flows.csv": "text/csv",
    "capture.pcap": "application/vnd.tcpdump.pcap",
    "meta.json": "application/json",
}

BENIGN_KINDS = ("icmp", "http", "service")

# Marges autour de la fenêtre d'une attaque (secondes) : l'horloge de l'hôte et
# celle de la machine Docker, qui horodate les paquets, peuvent légèrement différer.
WINDOW_BEFORE = 1.0
WINDOW_AFTER = 2.0

# Bornes du programme (garde-fous : une génération doit rester de durée raisonnable).
MAX_RUNS = 30
MAX_VARIANTS = 5

# Ordre de parcours des vitesses et fréquences de trafic bénin pour fabriquer les variantes.
SPEED_ORDER = ["slow", "normal", "fast", "insane"]
PROFILE_ORDER = ["slow", "moderate", "steady", "intense"]
PCAP_PATH = "/tmp/dataset.pcap"


class DatasetError(TrafficError):
    """Génération impossible ; le message est affichable tel quel."""


@dataclass
class BenignSource:
    node: str
    name: str
    targets: List[dict]


@dataclass
class AttackRun:
    """Une exécution d'attaque du programme, et sa fenêtre de temps une fois jouée."""

    attack: str
    name: str
    category: str
    subcategory: str
    needs: str
    source: str
    source_name: str
    source_ip: str
    target: str
    speed: str
    start: Optional[float] = None
    end: Optional[float] = None
    stopped_at_limit: bool = False
    exit_code: Optional[int] = None
    output: str = ""

    def matches(self, src: str, dst: str, ts: Optional[float]) -> bool:
        """Le flux (src → dst, commencé à ts) appartient-il à cette attaque ?"""
        if self.start is None or self.end is None or ts is None or src != self.source_ip:
            return False
        if not (self.start - WINDOW_BEFORE <= ts <= self.end + WINDOW_AFTER):
            return False
        try:
            if self.needs == "subnet":
                return ip_address(dst) in ip_network(self.target, strict=False)
            return ip_address(dst) == ip_address(self.target)
        except ValueError:
            return False


@dataclass
class DatasetPlan:
    name: str
    probe: str
    probe_name: str
    probe_ip: str
    kinds: List[str]
    profile: str
    benign: List[BenignSource]
    runs: List[AttackRun]
    warmup: int
    gap: int
    cooldown: int
    max_attack: int
    topology: dict = field(default_factory=dict)              # topologie du réseau : nom, empreinte, résumé
    variants: int = 0                                         # variantes de test à générer ensuite
    attackers: List[dict] = field(default_factory=list)       # machines pouvant jouer une attaque
    group: dict = field(default_factory=dict)                 # base / variante (voir make_variant)


def _timestamp_value(value: str) -> Optional[float]:
    """Horodatage d'un flux : format CICFlowMeter, ou secondes epoch (exporteur interne)."""
    parsed = parse_timestamp(value)
    if parsed is not None:
        return parsed
    try:
        return float(value)
    except ValueError:
        return None


def label_dataset_csv(csv_text: str, runs: List[AttackRun]):
    """Étiquette les flux d'un dataset d'après les fenêtres de ses attaques → (CSV, décompte, total)."""

    def label_of(src: str, dst: str, ts: str) -> str:
        moment = _timestamp_value(ts)
        for run in runs:
            if run.matches(src, dst, moment):
                return run.subcategory
        return "BENIGN"

    return relabel_csv(csv_text, label_of)


def topology_info(raw: Optional[dict]) -> dict:
    """
    Topologie sur laquelle un dataset est généré, telle que décrite par l'interface :
    `name` (exemple chargé ou « Topologie personnalisée »), `signature` (empreinte
    des équipements, adresses et réseaux : deux datasets de même empreinte viennent
    du même réseau) et `summary` (résumé lisible).
    """
    raw = raw or {}
    return {key: str(raw.get(key) or "")[:limit] for key, limit in (("name", 120), ("signature", 4000), ("summary", 200))}


# --------------------------------------------------------------------------- variantes


def make_variant(plan: DatasetPlan, k: int) -> DatasetPlan:
    """
    k-ième variante de test d'un programme : mêmes attaques, mêmes cibles et
    même sonde, mais chaque attaque part d'une AUTRE machine et à une AUTRE
    vitesse, et le trafic bénin change d'intensité. Le modèle est ainsi évalué
    sur des flux qu'il n'a jamais vus, sans changer la nature des attaques.
    Déterministe : la même demande produit les mêmes variantes.
    """
    changes: List[str] = []
    runs: List[AttackRun] = []
    for i, run in enumerate(plan.runs):
        candidates = [a for a in plan.attackers if a["node"] != run.source and a["ip"] != run.target]
        source = candidates[(i + k - 1) % len(candidates)] if candidates else None
        speeds = [sp for sp in SPEED_ORDER if sp != run.speed]
        speed = speeds[(i + k - 1) % len(speeds)]
        runs.append(replace(
            run, source=source["node"] if source else run.source, source_name=source["name"] if source else run.source_name,
            source_ip=source["ip"] if source else run.source_ip, speed=speed,
            start=None, end=None, stopped_at_limit=False, exit_code=None, output="",
        ))
        changes.append(
            f"{run.name} : {run.source_name} → {runs[-1].source_name}, "
            f"{SPEEDS[run.speed]['label'].lower()} → {SPEEDS[speed]['label'].lower()}"
        )
    profiles = [pr for pr in PROFILE_ORDER if pr != plan.profile]
    profile = profiles[(k - 1) % len(profiles)]
    changes.append(f"Trafic bénin : {BENIGN_PROFILES[plan.profile].split(' (')[0].lower()} → "
                   f"{BENIGN_PROFILES[profile].split(' (')[0].lower()}")
    return replace(plan, name=f"{plan.name} — variante {k}", runs=runs, profile=profile, variants=0,
                   group={"role": "variant", "index": k, "changes": changes})


# --------------------------------------------------------------------------- stockage


class DatasetStore(RecordStore):
    """Datasets sauvegardés sur disque : un dossier par dataset (voir store.py)."""

    def __init__(self, root: Path = DATA_DIR):
        super().__init__(root, FILES, DatasetError, "Dataset")


# --------------------------------------------------------------------------- génération


class DatasetBuilder:
    def __init__(self, traffic: TrafficManager, store: DatasetStore):
        self.traffic = traffic
        self.lab = traffic.lab
        self.store = store

    def _device(self, node_id: str, what: str):
        try:
            return self.traffic.require_device(node_id, what)
        except TrafficError as exc:
            raise DatasetError(str(exc)) from exc

    def prepare(self, spec: dict) -> DatasetPlan:
        """Vérifie le programme demandé par l'interface (avant de lancer la tâche)."""
        if not spec.get("probe"):
            raise DatasetError("Aucune Sonde IDS : ajoutez-en une à la topologie, c'est le point de capture du dataset.")
        probe = self._device(spec["probe"], "Sonde IDS")
        if probe.labels.get(f"{self.lab.settings.prefix}.type") != "ids":
            raise DatasetError("Le point de capture d'un dataset est toujours une Sonde IDS.")
        kinds = [k for k in spec.get("kinds") or [] if k in BENIGN_KINDS]
        profile = spec.get("profile") or "moderate"
        if profile not in BENIGN_PROFILES:
            raise DatasetError(f"Fréquence de trafic inconnue « {profile} ».")

        benign = []
        attackers: Dict[str, dict] = {}  # machines pouvant attaquer dans une variante
        for entry in spec.get("benign") or []:
            device = self._device(entry["node"], "Trafic bénin")
            if entry.get("targets"):
                benign.append(BenignSource(entry["node"], self.traffic.name_of(device), entry["targets"]))
                attackers[entry["node"]] = {"node": entry["node"], "name": self.traffic.name_of(device),
                                            "ip": self.traffic.device_ip(device)}
        if benign and not kinds:
            raise DatasetError("Choisissez au moins un type de trafic bénin.")

        runs: List[AttackRun] = []
        for entry in spec.get("attacks") or []:
            attack = ATTACKS.get(entry["attack"])
            if attack is None:
                raise DatasetError(f"Attaque inconnue « {entry['attack']} ».")
            target = (entry.get("target") or "").strip()
            if not TARGET_RE.match(target):
                raise DatasetError(f"{attack['name']} : cible invalide (adresse IP ou sous-réseau attendu).")
            speed = entry.get("speed") or "fast"
            if speed not in SPEEDS:
                raise DatasetError(f"Vitesse inconnue « {speed} ».")
            device = self._device(entry["source"], attack["name"])
            attackers.setdefault(entry["source"], {"node": entry["source"], "name": self.traffic.name_of(device),
                                                   "ip": self.traffic.device_ip(device)})
            category, subcategory = attack["label"]
            for _ in range(int(entry.get("repeat") or 1)):
                runs.append(AttackRun(
                    attack=entry["attack"], name=attack["name"], category=category, subcategory=subcategory,
                    needs=attack["needs"], source=entry["source"], source_name=self.traffic.name_of(device),
                    source_ip=self.traffic.device_ip(device), target=target, speed=speed,
                ))
        if not runs:
            raise DatasetError("Ajoutez au moins une attaque au programme.")
        if len(runs) > MAX_RUNS:
            raise DatasetError(f"Programme trop long : {len(runs)} attaques (maximum {MAX_RUNS}).")

        return DatasetPlan(
            name=(spec.get("name") or "").strip()[:80] or "Dataset sans nom",
            probe=spec["probe"], probe_name=self.traffic.name_of(probe), probe_ip=self.traffic.device_ip(probe),
            kinds=kinds, profile=profile, benign=benign, runs=runs,
            warmup=int(spec["warmup"]), gap=int(spec["gap"]), cooldown=int(spec["cooldown"]),
            max_attack=int(spec["maxAttack"]),
            topology=topology_info(spec.get("topology")),
            variants=max(0, min(MAX_VARIANTS, int(spec.get("variants") or 0))),
            attackers=list(attackers.values()),
        )

    # ------------------------------------------------------------------ tâche de fond

    def run(self, plan: DatasetPlan, job: Job) -> dict:
        """
        Joue le programme et en tire un dataset étiqueté, puis ses variantes de test
        éventuelles (voir make_variant). Renvoie la description du dataset de base
        et de tous les datasets produits.
        """
        plans = [plan] + [make_variant(plan, k) for k in range(1, plan.variants + 1)]
        # Étapes par dataset : démarrage, bénin initial, attaques (+ pauses), bénin final, flux, sauvegarde.
        job.begin(sum(2 * len(p.runs) + 4 for p in plans))
        metas: List[dict] = []
        for i, current in enumerate(plans):
            tag = "" if not plan.variants else ("[Base] " if i == 0 else f"[Variante {i}/{plan.variants}] ")
            if i == 0 and plan.variants:
                current.group = {"role": "base", "variants": plan.variants}
            elif i:
                current.group = {**current.group, "of": metas[0]["id"]}
            metas.append(self._generate(current, job, tag))
        return {"dataset": metas[0], "datasets": metas}

    def _generate(self, plan: DatasetPlan, job: Job, tag: str = "") -> dict:
        """Joue un programme, puis extrait et étiquette les flux. Renvoie la description du dataset."""
        runs = plan.runs
        step = lambda label: job.step(tag + label)  # noqa: E731 - préfixe « [Variante k/n] » des étapes
        began = time.time()
        capture = None
        running_agents: set = set()
        try:
            step(f"Démarrage de la sonde sur {plan.probe_name} et du trafic bénin")
            probe = self._device(plan.probe, "Sonde IDS")
            interface = self.traffic.primary_interface(probe)
            # Le programme prend la main sur le trafic bénin : un agent lancé à la main
            # (configuration inconnue) fausserait l'étiquetage de la source d'une attaque.
            if self.traffic.stop_benign():
                job.warn("Le trafic bénin déjà en cours a été arrêté : le programme le remplace.")
            try:
                # Mode promiscuité (pas de -p) : la Sonde IDS reçoit la copie du trafic de
                # tout le segment (switch en mode hub).
                capture = self.lab.start_netns_helper(
                    probe, self.lab.settings.capture,
                    ["tcpdump", "-i", interface, "-U", "-w", PCAP_PATH],
                    role="dcapture", attached=plan.probe,
                )
            except DockerException as exc:
                raise DatasetError("Impossible de démarrer la sonde de capture.") from exc
            for source in plan.benign:
                self._start_benign(plan, source)
                running_agents.add(source.node)

            step(f"Trafic bénin seul ({plan.warmup} s)")
            job.sleep(plan.warmup)

            for i, run in enumerate(runs):
                if i:
                    step(f"Trafic bénin entre deux attaques ({plan.gap} s)")
                    job.sleep(plan.gap)
                step(
                    f"Attaque {i + 1}/{len(runs)} : {run.name} ({SPEEDS[run.speed]['label'].lower()}) "
                    f"— {run.source_name} → {run.target}"
                )
                self._play(plan, run, job, paused=run.source in running_agents)

            step(f"Trafic bénin final ({plan.cooldown} s)")
            job.sleep(plan.cooldown)
        except BaseException:
            self._remove(capture)
            raise
        finally:
            for node in running_agents:
                self.traffic.stop_benign(node)

        try:
            step(f"Extraction des flux (CICFlowMeter, fenêtres de {FLOW_WINDOW_SEC} s comme en détection)")
            time.sleep(1.5)  # laisse les derniers paquets arriver
            try:
                capture.stop(timeout=3)  # tcpdump vide son tampon et écrit le pcap
            except DockerException:
                pass
            try:
                pcap = self.traffic.extract_file(capture, PCAP_PATH)
            except (DockerException, ValueError) as exc:
                raise DatasetError("Le pcap de la sonde est introuvable.") from exc
        finally:
            self._remove(capture)

        try:
            # Découpé en fenêtres comme en détection en direct : le modèle apprend sur des
            # flux préparés exactement comme ceux qu'il classera (un ping n'y forme pas
            # un seul long flux, mais un court flux par fenêtre).
            raw_csv = windowed_flows_csv(self.lab, pcap)
            engine = "CICFlowMeter"
        except Exception as exc:  # noqa: BLE001 - Docker/image absents : repli sur l'exporteur interne
            log.warning("CICFlowMeter indisponible (%s) : repli sur l'exporteur interne", exc)
            job.warn("CICFlowMeter indisponible : flux calculés par l'exporteur interne (colonnes réduites).")
            parts = [flows_to_csv(build_flows(parse_pcap(chunk))) for chunk in split_pcap(pcap, FLOW_WINDOW_SEC)]
            raw_csv = parts[0] + "".join(part.split("\n", 1)[1] for part in parts[1:]) if parts else ""
            engine = "interne"

        step("Étiquetage et sauvegarde")
        csv_text, counts, total = label_dataset_csv(raw_csv, runs)
        if not any(label != "BENIGN" for label in counts):
            job.warn("Aucun flux d'attaque n'a été vu par la Sonde IDS : surveille-t-elle le switch traversé par les attaques ?")

        dataset_id = self.store.new_id()
        meta = self._meta(dataset_id, plan, began, engine, counts, total, len(pcap))
        self.store.save(dataset_id, meta, {"flows.csv": csv_text, "capture.pcap": pcap})
        log.info("Dataset %s : %d flux %s (%s)", dataset_id, total, counts, engine)
        return meta

    def _start_benign(self, plan: DatasetPlan, source: BenignSource) -> None:
        try:
            self.traffic.start_benign(source.node, plan.profile, source.targets, "dataset", plan.kinds)
        except TrafficError as exc:
            raise DatasetError(f"Trafic bénin sur {source.name} : {exc}") from exc

    def _play(self, plan: DatasetPlan, run: AttackRun, job: Job, paused: bool) -> None:
        """Joue une attaque et enregistre sa fenêtre de temps (bornée par plan.max_attack)."""
        device = self._device(run.source, run.name)
        if paused:
            self.traffic.stop_benign(run.source)  # la source ne fait que l'attaque pendant sa fenêtre
        command = ATTACKS[run.attack]["command"](run.target, run.speed)
        helper = None
        run.start = time.time()
        try:
            try:
                helper = self.lab.start_netns_helper(
                    device, self.lab.settings.traffic, command,
                    role="dataset", attached=run.source, attack=run.attack, target=run.target,
                )
            except DockerException as exc:
                raise DatasetError(f"Impossible de lancer « {run.name} ».") from exc
            deadline = run.start + plan.max_attack
            while True:
                helper.reload()
                if helper.status != "running":
                    break
                if time.time() >= deadline:
                    run.stopped_at_limit = True
                    helper.kill()
                    break
                job.sleep(0.5)
            run.end = time.time()
            helper.reload()
            run.exit_code = helper.attrs.get("State", {}).get("ExitCode")
            run.output = helper.logs().decode(errors="replace")[-2000:]
        finally:
            if run.end is None:
                run.end = time.time()
            self._remove(helper)
            if paused:
                for source in plan.benign:
                    if source.node == run.source:
                        self._start_benign(plan, source)

    @staticmethod
    def _remove(container) -> None:
        if container is None:
            return
        try:
            container.remove(force=True)
        except DockerException:
            pass

    @staticmethod
    def _meta(dataset_id: str, plan: DatasetPlan, began: float, engine: str, counts: Dict[str, int], total: int, pcap_size: int) -> dict:
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")
        return {
            "id": dataset_id,
            "name": plan.name,
            "createdAt": iso(began),
            "durationSec": round(time.time() - began),
            "engine": engine,
            "total": total,
            "counts": counts,
            "pcapBytes": pcap_size,
            "probe": {"node": plan.probe, "name": plan.probe_name, "ip": plan.probe_ip},
            "benign": {
                "sources": [{"node": s.node, "name": s.name} for s in plan.benign],
                "kinds": plan.kinds,
                "profile": plan.profile,
            },
            "attacks": [
                {**{k: v for k, v in asdict(r).items() if k not in ("start", "end")},
                 "start": iso(r.start) if r.start else None, "end": iso(r.end) if r.end else None,
                 "durationSec": round(r.end - r.start, 1) if r.start and r.end else None}
                for r in plan.runs
            ],
            "params": {"warmup": plan.warmup, "gap": plan.gap, "cooldown": plan.cooldown, "maxAttack": plan.max_attack},
            "group": plan.group or None,
            "topology": plan.topology or None,
            "flowWindowSec": FLOW_WINDOW_SEC,
        }
