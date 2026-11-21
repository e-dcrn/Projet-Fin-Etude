"""
Génération d'un dataset étiqueté sur le réseau instancié.

Un dataset est produit par une tâche de fond (voir jobs.py) qui joue un
programme complet sur la topologie déployée :

  1. la SONDE IDS capture le trafic du segment qu'elle surveille (c'est le seul
     point de capture : une topologie sans Sonde IDS ne permet pas de dataset) ;
  2. des agents de trafic bénin tournent pendant toute la durée ;
  3. les attaques s'enchaînent, une à la fois, entrecoupées de trafic bénin
     seul ; la fenêtre de temps de chaque attaque est enregistrée ;
  4. le pcap est converti en flux CICFlowMeter ;
  5. chaque flux est étiqueté : « attaque » s'il va de la source vers la cible
     d'une attaque ET commence pendant sa fenêtre, « BENIGN » sinon. Pendant son
     attaque, la source ne fait pas de trafic bénin, ce qui rend la règle exacte.

Le résultat est sauvegardé dans data/datasets/<id>/ (flows.csv, capture.pcap,
meta.json) : il survit à l'arrêt du réseau.
"""

import logging
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import List, Optional

from docker.errors import DockerException

from .cicflowmeter import FLOW_WINDOW_SEC, parse_timestamp, relabel_csv, windowed_flows_csv
from .errors import UserError
from .models import SERVICE_KINDS
from .settings import DATA_DIR, PREFIX
from .store import RecordStore
from .traffic import ATTACKS, BENIGN_PROFILES, SPEEDS, TARGET_RE, TrafficManager

log = logging.getLogger(__name__)

# Fichiers d'un dataset téléchargeables depuis l'interface → type MIME.
FILES = {
    "flows.csv": "text/csv",
    "capture.pcap": "application/vnd.tcpdump.pcap",
    "meta.json": "application/json",
}

BENIGN_KINDS = ("icmp", "tcp", *SERVICE_KINDS)  # ping, ports TCP sans service connu, un type par service

# Marges autour de la fenêtre d'une attaque (s) : l'horloge de l'hôte et celle de
# la machine Docker, qui horodate les paquets, peuvent légèrement différer.
WINDOW_BEFORE = 1.0
WINDOW_AFTER = 2.0

MAX_RUNS = 30      # garde-fou : une génération doit rester de durée raisonnable
MAX_VARIANTS = 5
PCAP_PATH = "/tmp/dataset.pcap"

# Ordre de parcours des vitesses et des fréquences pour fabriquer les variantes.
SPEED_ORDER = ["slow", "normal", "fast", "insane"]
PROFILE_ORDER = ["slow", "moderate", "steady", "intense"]


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

    def matches(self, src, dst, ts):
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
    variants: int = 0                                   # variantes de test à générer ensuite
    attackers: List[dict] = field(default_factory=list)  # machines pouvant jouer une attaque (pour les variantes)
    group: dict = field(default_factory=dict)            # base / variante (voir make_variant)


def label_dataset_csv(csv_text, runs):
    """Étiquette les flux d'après les fenêtres des attaques → (CSV, décompte, total)."""

    def label_of(src, dst, ts):
        moment = parse_timestamp(ts)
        for run in runs:
            if run.matches(src, dst, moment):
                return run.subcategory
        return "BENIGN"

    return relabel_csv(csv_text, label_of)


def failure_warning(run):
    """Message si l'outil d'attaque a échoué : ses flux ne représentent alors pas l'attaque annoncée."""
    if run.stopped_at_limit or run.exit_code in (None, 0):
        return None  # terminée normalement, ou arrêtée par la durée maximale du programme
    detail = run.output.strip().splitlines()[-1] if run.output.strip() else "aucune sortie"
    return (f"{run.name} ({run.source_name} → {run.target}) a échoué (code {run.exit_code}) : {detail[:160]}. "
            "Ses flux ne représentent pas cette attaque : vérifiez que la cible ouvre le service visé.")


def make_variant(plan, k):
    """
    k-ième variante de test d'un programme : mêmes attaques, mêmes cibles et même
    sonde, mais chaque attaque part d'une AUTRE machine à une AUTRE vitesse, et le
    trafic bénin change d'intensité. Le modèle est ainsi évalué sur des flux qu'il
    n'a jamais vus, sans changer la nature des attaques. Déterministe.
    """
    changes = []
    runs = []
    for i, run in enumerate(plan.runs):
        candidates = [a for a in plan.attackers if a["node"] != run.source and a["ip"] != run.target]
        source = candidates[(i + k - 1) % len(candidates)] if candidates else None
        speeds = [sp for sp in SPEED_ORDER if sp != run.speed]
        speed = speeds[(i + k - 1) % len(speeds)]
        runs.append(replace(
            run,
            source=source["node"] if source else run.source,
            source_name=source["name"] if source else run.source_name,
            source_ip=source["ip"] if source else run.source_ip,
            speed=speed, start=None, end=None, stopped_at_limit=False, exit_code=None, output="",
        ))
        changes.append(f"{run.name} : {run.source_name} → {runs[-1].source_name}, "
                       f"{SPEEDS[run.speed]['label'].lower()} → {SPEEDS[speed]['label'].lower()}")
    profile = [pr for pr in PROFILE_ORDER if pr != plan.profile][(k - 1) % (len(PROFILE_ORDER) - 1)]
    changes.append(f"Trafic bénin : {BENIGN_PROFILES[plan.profile].split(' (')[0].lower()} → "
                   f"{BENIGN_PROFILES[profile].split(' (')[0].lower()}")
    return replace(plan, name=f"{plan.name} — variante {k}", runs=runs, profile=profile, variants=0,
                   group={"role": "variant", "index": k, "changes": changes})


class DatasetStore(RecordStore):
    """Datasets sauvegardés sur disque : un dossier par dataset (voir store.py)."""

    def __init__(self, root: Path = DATA_DIR / "datasets"):
        super().__init__(root, FILES, "Dataset")


class DatasetBuilder:
    def __init__(self, traffic: TrafficManager, store: DatasetStore):
        self.traffic = traffic
        self.lab = traffic.lab
        self.store = store

    def prepare(self, spec):
        """
        Vérifie le programme AVANT de lancer la tâche (qui dure plusieurs minutes),
        et résout chaque équipement en son conteneur et son adresse IP.
        """
        if not spec.get("probe"):
            raise UserError("Aucune Sonde IDS : ajoutez-en une à la topologie, c'est le point de capture du dataset.")
        probe = self.traffic.require_device(spec["probe"], "Sonde IDS")
        if probe.labels.get(f"{PREFIX}.type") != "ids":
            raise UserError("Le point de capture d'un dataset est toujours une Sonde IDS.")
        kinds = [k for k in spec.get("kinds") or [] if k in BENIGN_KINDS]

        benign = []
        attackers = {}  # machines pouvant attaquer dans une variante : node → {node, name, ip}
        for entry in spec.get("benign") or []:
            device = self.traffic.require_device(entry["node"], "Trafic bénin")
            if entry.get("targets"):
                info = {"node": entry["node"], "name": self.traffic.name_of(device), "ip": self.traffic.device_ip(device)}
                benign.append(BenignSource(entry["node"], info["name"], entry["targets"]))
                attackers[entry["node"]] = info
        if benign and not kinds:
            raise UserError("Choisissez au moins un type de trafic bénin.")

        runs = []
        for entry in spec.get("attacks") or []:
            attack = ATTACKS[entry["attack"]]
            target = (entry.get("target") or "").strip()
            if not TARGET_RE.match(target):  # la cible entre dans une commande shell : on la restreint
                raise UserError(f"{attack['name']} : cible invalide (adresse IP ou sous-réseau attendu).")
            device = self.traffic.require_device(entry["source"], attack["name"])
            name, ip = self.traffic.name_of(device), self.traffic.device_ip(device)
            attackers.setdefault(entry["source"], {"node": entry["source"], "name": name, "ip": ip})
            category, subcategory = attack["label"]
            for _ in range(int(entry.get("repeat") or 1)):
                runs.append(AttackRun(
                    attack=entry["attack"], name=attack["name"], category=category, subcategory=subcategory,
                    needs=attack["needs"], source=entry["source"], source_name=name, source_ip=ip,
                    target=target, speed=entry.get("speed") or "fast",
                ))
        if not runs:
            raise UserError("Ajoutez au moins une attaque au programme.")
        if len(runs) > MAX_RUNS:
            raise UserError(f"Programme trop long : {len(runs)} attaques (maximum {MAX_RUNS}).")

        return DatasetPlan(
            name=(spec.get("name") or "").strip()[:80] or "Dataset sans nom",
            probe=spec["probe"], probe_name=self.traffic.name_of(probe), probe_ip=self.traffic.device_ip(probe),
            kinds=kinds, profile=spec.get("profile") or "moderate", benign=benign, runs=runs,
            warmup=int(spec["warmup"]), gap=int(spec["gap"]), cooldown=int(spec["cooldown"]),
            max_attack=int(spec["maxAttack"]),
            variants=max(0, min(MAX_VARIANTS, int(spec.get("variants") or 0))),
            attackers=list(attackers.values()),
        )

    def run(self, plan, job):
        """
        Joue le programme, puis ses variantes de test éventuelles (voir make_variant).
        Renvoie la description du dataset de base et de tous les datasets produits.
        """
        plans = [plan] + [make_variant(plan, k) for k in range(1, plan.variants + 1)]
        # Étapes par dataset : démarrage, bénin initial, attaques (+ pauses), bénin final, flux, sauvegarde.
        job.begin(sum(2 * len(p.runs) + 4 for p in plans))
        metas = []
        for i, current in enumerate(plans):
            tag = "" if not plan.variants else ("[Base] " if i == 0 else f"[Variante {i}/{plan.variants}] ")
            if i == 0 and plan.variants:
                current.group = {"role": "base", "variants": plan.variants}
            elif i:
                current.group = {**current.group, "of": metas[0]["id"]}
            metas.append(self._generate(current, job, tag))
        return {"dataset": metas[0], "datasets": metas}

    def _generate(self, plan, job, tag=""):
        """Joue un programme, puis extrait et étiquette les flux. Renvoie la description du dataset."""
        runs = plan.runs
        step = lambda label: job.step(tag + label)  # noqa: E731 - préfixe « [Variante k/n] » des étapes
        began = time.time()
        probe = self.traffic.require_device(plan.probe, "Sonde IDS")
        interface = self.traffic.primary_interface(probe)

        # Le programme prend la main sur le trafic bénin : un agent lancé à la main
        # (configuration inconnue) fausserait l'étiquetage de la source d'une attaque.
        step(f"Démarrage de la sonde sur {plan.probe_name} et du trafic bénin")
        if self.traffic.stop_benign():
            job.warn("Le trafic bénin déjà en cours a été arrêté : le programme le remplace.")
        # Mode promiscuité (pas de -p) : la sonde reçoit la copie du trafic de tout le segment.
        capture = self.lab.start_netns_helper(
            probe, ["tcpdump", "-i", interface, "-U", "-w", PCAP_PATH], role="dcapture", attached=plan.probe,
        )
        for source in plan.benign:
            self.traffic.start_benign(source.node, plan.profile, source.targets, "dataset", plan.kinds)

        try:
            step(f"Trafic bénin seul ({plan.warmup} s)")
            job.sleep(plan.warmup)
            for i, run in enumerate(runs):
                if i:
                    step(f"Trafic bénin entre deux attaques ({plan.gap} s)")
                    job.sleep(plan.gap)
                step(f"Attaque {i + 1}/{len(runs)} : {run.name} ({SPEEDS[run.speed]['label'].lower()}) "
                     f"— {run.source_name} → {run.target}")
                self._play(plan, run, job, paused=any(s.node == run.source for s in plan.benign))
                warning = failure_warning(run)
                if warning:
                    job.warn(tag + warning)
            step(f"Trafic bénin final ({plan.cooldown} s)")
            job.sleep(plan.cooldown)

            step(f"Extraction des flux (CICFlowMeter, fenêtres de {FLOW_WINDOW_SEC} s comme en détection)")
            time.sleep(1.5)            # laisse les derniers paquets arriver
            capture.stop(timeout=3)    # tcpdump vide son tampon et écrit le pcap
            pcap = self.traffic.extract_file(capture, PCAP_PATH)
        finally:
            for source in plan.benign:
                self.traffic.stop_benign(source.node)
            _remove(capture)

        # Découpé en fenêtres comme en détection en direct, pour que le modèle apprenne
        # sur des flux préparés exactement comme ceux qu'il classera.
        raw_csv = windowed_flows_csv(self.lab, pcap)
        step("Étiquetage et sauvegarde")
        csv_text, counts, total = label_dataset_csv(raw_csv, runs)
        if not any(label != "BENIGN" for label in counts):
            job.warn("Aucun flux d'attaque n'a été vu par la Sonde IDS : surveille-t-elle le switch traversé par les attaques ?")

        dataset_id = self.store.new_id()
        meta = self._meta(dataset_id, plan, began, counts, total, len(pcap))
        self.store.save(dataset_id, meta, {"flows.csv": csv_text, "capture.pcap": pcap})
        log.info("Dataset %s : %d flux %s", dataset_id, total, counts)
        return meta

    def _play(self, plan, run, job, paused):
        """Joue une attaque et enregistre sa fenêtre de temps (bornée par plan.max_attack)."""
        device = self.traffic.require_device(run.source, run.name)
        if paused:
            self.traffic.stop_benign(run.source)  # la source ne fait que l'attaque pendant sa fenêtre
        command = ATTACKS[run.attack]["command"](run.target, run.speed)
        run.start = time.time()
        deadline = run.start + plan.max_attack
        helper = None
        try:
            helper = self.lab.start_netns_helper(
                device, command, role="dataset", attached=run.source, attack=run.attack, target=run.target,
            )
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
            _remove(helper)
            if paused:
                time.sleep(WINDOW_AFTER)  # l'agent ne reprend qu'après la marge de fin d'attaque de l'étiquetage
                for source in plan.benign:
                    if source.node == run.source:
                        self.traffic.start_benign(source.node, plan.profile, source.targets, "dataset", plan.kinds)

    def _meta(self, dataset_id, plan, began, counts, total, pcap_size):
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")  # noqa: E731
        return {
            "id": dataset_id,
            "name": plan.name,
            "createdAt": iso(began),
            "durationSec": round(time.time() - began),
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
            "flowWindowSec": FLOW_WINDOW_SEC,
        }


def _remove(container):
    """Supprime un conteneur sans échouer s'il a déjà disparu."""
    if container is None:
        return
    try:
        container.remove(force=True)
    except DockerException:
        pass
