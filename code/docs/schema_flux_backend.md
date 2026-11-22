# Carte des appels du backend

Toutes les fonctions définies dans `backend/app/` (le front est écarté : généré par IA).
Un diagramme par module/sous-système.

**Convention de lecture :**

- **Flèche `A --> B`** : `A` appelle `B` (ou les deux se suivent dans l'ordre d'exécution).
- **Boîte englobante (`subgraph`)** : un module ou une classe. Les fonctions dedans sont ses
  méthodes/fonctions ; un appel qui reste dans la boîte est un **appel interne**, un appel qui
  en sort pointe vers une autre boîte (souvent un autre module).
- **Couleurs** (classes en bas de chaque diagramme) :
  - `entry` = route de l'API (`main.py`)
  - `pub` = méthode publique / orchestrateur
  - `aux` = helper interne (nom en `_`)
  - `pure` = fonction de module sans état (testable isolément)
  - `ext` = cible hors du module courant (autre manager, Docker, lib externe)

> Les blocs ` ```mermaid ` se rendent directement sur GitHub et dans la plupart des éditeurs
> Markdown. Fais ton tri en éditant le texte.

---

## Flux d'exécution global — du démarrage à l'extinction

Le déroulé chronologique d'une démo complète. **Une seule colonne** tant que c'est séquentiel
(un bloc, une flèche vers le suivant). **Dès qu'un thread ou un conteneur tourne en parallèle**,
une flèche part sur le côté (flèche en pointillé) pendant que la colonne principale continue tout
droit ; elle rejoint la colonne plus bas au point de synchronisation (`done`, reprise…).

- Bleu = action de l'utilisateur · Gris = réponse du backend (fil principal) · Pointillé clair = attente/polling
- Orange = étape d'un **thread** de fond · Vert = **conteneur** Docker en parallèle · Rouge = extinction

```mermaid
flowchart TD
  S0["① Lancement du backend<br/>uvicorn app.main:app<br/>crée lab, traffic, jobs, detection…"]:::act
  S1["② « Démarrer le réseau »<br/>POST /api/lab"]:::act
  S2["lab.start() : docker compose up --build<br/>réseau en marche"]:::api
  S3["③ « Nouveau dataset » → Générer<br/>POST /api/datasets"]:::act
  S4["prepare() + jobs.start('dataset')<br/>renvoie {id} aussitôt"]:::api
  S5["Frontend interroge /api/jobs/{id} ~1 s<br/>jusqu'à « done »"]:::sync
  S6["④ « Entraîner un modèle »<br/>POST /api/models"]:::act
  S7["prepare() + jobs.start('training')<br/>renvoie {id}"]:::api
  S8["Polling jusqu'à « done »<br/>modèle prêt"]:::sync
  S9["⑤ « Détection ▶ »<br/>POST /api/lab/detection"]:::act
  S10["start() : lance capture + thread _loop<br/>renvoie l'état"]:::api
  S11["⑥ « Trafic bénin ▶ »<br/>POST /api/lab/traffic/benign"]:::act
  S12["⑦ « Lancer l'attaque »<br/>POST /api/lab/scenarios"]:::act
  S13["run_scenario() : pause bénin, lance attaque,<br/>thread _resume_after — renvoie le scénario"]:::api
  S14["Frontend lit /api/lab/detection ~2 s<br/>alertes · manquées · fausses alertes"]:::sync
  S15["⑧ « Détection ■ »<br/>DELETE /api/lab/detection → _cleanup()"]:::act
  S16["⑨ « Réseau ■ »<br/>DELETE /api/lab<br/>lab.stop() : remove helpers + compose down"]:::act
  S17["⑩ Extinction du backend<br/>Ctrl-C uvicorn"]:::fin

  S0 --> S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9
  S9 --> S10 --> S11 --> S12 --> S13 --> S14 --> S15 --> S16 --> S17

  D1["thread : DatasetBuilder.run"]:::thr
  D2["_generate : tcpdump sur la sonde"]:::thr
  D3["warmup → boucle _play(attaques) → cooldown"]:::thr
  D4["windowed_flows_csv → label → store.save"]:::thr
  D5["job « done »"]:::thr
  DC1(["conteneurs parallèles :<br/>capture + agents bénins"]):::cont
  S4 -.->|thread de fond| D1
  D1 --> D2 --> D3 --> D4 --> D5
  D2 -.->|lance| DC1
  D5 -.->|done| S5

  T1["thread : Trainer.run"]:::thr
  T2["load_frames → feature_matrix"]:::thr
  T3["RandomForest.fit"]:::thr
  T4["evaluate + by_attack"]:::thr
  T5["store.save model.joblib → « done »"]:::thr
  S7 -.->|thread de fond| T1
  T1 --> T2 --> T3 --> T4 --> T5
  T5 -.->|done| S8

  LC(["conteneur tcpdump -G 5<br/>1 pcap toutes les 5 s"]):::cont
  L1["thread _loop : réveil toutes les 1 s"]:::thr
  L2["_tick : fenêtres finies → convert"]:::thr
  L3["_classify : predict + vérité terrain → outcome_of"]:::thr
  L4["compteurs de la Session ++"]:::thr
  S10 -.->|thread persistant| L1
  L1 --> L2 --> L3 --> L4
  L4 -.->|boucle 1 s| L1
  S10 -.->|lance| LC
  LC -.->|fenêtres 5 s| L2
  S15 -.->|stop : lève session.stop| L1

  B1(["conteneur agent bénin<br/>traffic_agent.worker (boucle)"]):::cont
  S11 -.->|lance| B1
  K1(["conteneur attaque<br/>nmap / hydra"]):::cont
  K2["thread _resume_after :<br/>attend la fin → relance le bénin"]:::thr
  S13 -.->|lance| K1
  S13 -.->|thread| K2
  S13 -.->|pause| B1
  K1 -.->|fin| K2
  K2 -.->|reprise| B1
  K1 -.->|labels = vérité terrain| L3

  classDef act fill:#2f6fdb,stroke:#1b4ba3,color:#fff;
  classDef api fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
  classDef sync fill:#fff,stroke:#c4cad6,color:#5b6472,stroke-dasharray:4 3;
  classDef thr fill:#f7e2cf,stroke:#d9772a,color:#1a1f29;
  classDef cont fill:#d3efe0,stroke:#2fa36a,color:#1a1f29;
  classDef fin fill:#f6d6dc,stroke:#d8465c,color:#1a1f29;
```

---

# Détail des appels par module

Les diagrammes suivants détaillent, module par module, qui appelle qui à l'intérieur de chaque
étape du flux global ci-dessus.

## 0. Vue d'ensemble — `main.py` crée les objets et route les requêtes

```mermaid
flowchart LR
  subgraph MAIN["main.py (API FastAPI)"]
    direction TB
    rLab["/api/lab (GET/POST/DELETE)"]:::entry
    rTraf["/api/lab/traffic*, /scenarios*"]:::entry
    rJobs["/api/jobs/{id}, /cancel"]:::entry
    rDs["/api/datasets*"]:::entry
    rMod["/api/models*"]:::entry
    rDet["/api/lab/detection*"]:::entry
    findJob["find_job()"]:::aux
    curJob["current_job_id()"]:::aux
  end

  lab["LabManager — lab.py"]:::ext
  traffic["TrafficManager — traffic.py"]:::ext
  dsStore["DatasetStore — store.py"]:::ext
  dsBuild["DatasetBuilder — datasets.py"]:::ext
  modStore["ModelStore — store.py"]:::ext
  trainer["Trainer — training.py"]:::ext
  detection["DetectionManager — detection.py"]:::ext
  jobs["JobRegistry — jobs.py"]:::ext

  traffic --> lab
  dsBuild --> traffic & dsStore
  trainer --> dsStore & modStore
  detection --> traffic & modStore

  rLab --> lab
  rLab --> detection
  rTraf --> traffic
  rJobs --> findJob --> jobs
  curJob --> jobs
  rDs --> dsBuild & dsStore & jobs
  rMod --> trainer & modStore & jobs
  rDet --> detection

  classDef entry fill:#2f6fdb,stroke:#1b4ba3,color:#fff;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
  classDef aux fill:#fff,stroke:#c4cad6,color:#5b6472,stroke-dasharray:4 3;
```

---

## 1. `lab.py` — pont Docker (topologie + conteneurs auxiliaires)

```mermaid
flowchart TD
  subgraph LAB["lab.py"]
    labels["labels()"]:::pure
    compose["compose()"]:::pure
    subgraph LM["class LabManager"]
      client["client (property)"]:::aux
      start["start()"]:::pub
      stop["stop()"]:::pub
      devices["devices()"]:::pub
      status["status()"]:::pub
      findDev["find_device()"]:::pub
      helpers["helpers()"]:::pub
      helper["start_netns_helper()"]:::pub
    end
  end

  dockerCLI(["docker compose (subprocess)"]):::ext
  dockerSDK(["SDK Docker (client)"]):::ext

  start --> stop
  start --> compose
  stop --> helpers
  stop --> compose
  status --> devices
  findDev --> devices
  devices --> client
  helpers --> client
  helper --> client
  helper --> labels
  compose --> dockerCLI
  client --> dockerSDK

  classDef pub fill:#2f6fdb,stroke:#1b4ba3,color:#fff;
  classDef aux fill:#dce6fa,stroke:#2f6fdb,color:#1a1f29;
  classDef pure fill:#fff,stroke:#2f6fdb,color:#2f6fdb;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

## 2. `traffic.py` — trafic bénin, attaques, vérité terrain

```mermaid
flowchart TD
  subgraph TRAF["traffic.py"]
    nmap["_nmap_cmd()"]:::pure
    hydra["_hydra_cmd() → build()"]:::pure
    stealth["_ftp_stealth_cmd()"]:::pure
    think["think()"]:::pure
    pad["pad()"]:::pure
    attempt["attempt()"]:::pure
    preview["command_preview()"]:::pure
    atkCat["attack_catalog()"]:::pure
    spdCat["speed_catalog()"]:::pure
    atkRes["attack_result()"]:::pure
    dTime["docker_time()"]:::pure
    ATTACKS[["ATTACKS / SPEEDS (catalogues)"]]:::pure

    subgraph TM["class TrafficManager"]
      reqDev["require_device()"]:::pub
      nameOf["name_of()"]:::pub
      devIp["device_ip()"]:::pub
      primIf["primary_interface()"]:::pub
      extract["extract_file()"]:::pub
      startBen["start_benign()"]:::pub
      stopBen["stop_benign()"]:::pub
      runScen["run_scenario()"]:::pub
      listScen["list_scenarios()"]:::pub
      stopScen["stop_scenarios()"]:::pub
      clrScen["clear_scenarios()"]:::pub
      overview["overview()"]:::pub
      pause["_pause_benign()"]:::aux
      resume["_resume_benign()"]:::aux
      resAfter["_resume_after()"]:::aux
      waitFin["_wait_until_finished()"]:::aux
      scenInfo["_scenario_info()"]:::aux
    end
  end

  labEXT["lab.start_netns_helper / helpers / find_device"]:::ext
  agentEXT["traffic_agent.py (dans le conteneur)"]:::ext

  nmap --> ATTACKS
  hydra --> ATTACKS
  stealth --> ATTACKS
  stealth --> think & pad & attempt

  findDev2["lab.find_device"]:::ext
  reqDev --> findDev2
  startBen --> reqDev & stopBen & nameOf
  startBen --> labEXT
  startBen --> agentEXT
  stopBen --> labEXT
  runScen --> reqDev & pause & scenInfo & nameOf
  runScen --> labEXT
  runScen --> resAfter
  listScen --> scenInfo
  listScen --> labEXT
  stopScen --> labEXT
  clrScen --> labEXT
  overview --> listScen & labEXT
  pause --> stopBen & labEXT
  resume --> labEXT
  resAfter --> waitFin & resume
  scenInfo --> dTime & atkRes & preview

  classDef pub fill:#d9772a,stroke:#a95712,color:#fff;
  classDef aux fill:#f7e2cf,stroke:#d9772a,color:#1a1f29;
  classDef pure fill:#fff,stroke:#d9772a,color:#a95712;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

## 3. `traffic_agent.py` — le « faux utilisateur » (exécuté DANS le conteneur toolbox)

```mermaid
flowchart TD
  subgraph AGENT["traffic_agent.py"]
    quiet["quiet()"]:::pure
    buildAct["build_actions()"]:::pure
    worker["worker()"]:::pure
    main["main()"]:::pub
    subgraph USER["class User"]
      uInit["__init__()"]:::aux
      uThink["think()"]:::aux
      uTypo["typo()"]:::aux
      uWeb["web() → get()"]:::pub
      uSsh["ssh()"]:::pub
      uFtp["ftp()"]:::pub
      uPing["ping()"]:::pub
    end
  end

  shellEXT(["curl / sshpass / ftplib / ping (shell)"]):::ext

  main --> buildAct
  main --> worker
  main --> uInit
  worker --> uWeb & uSsh & uFtp & uPing
  uWeb --> uThink & uTypo
  uSsh --> quiet & uThink & uTypo
  uFtp --> uThink & uTypo
  uWeb & uSsh & uFtp & uPing --> shellEXT
  quiet --> shellEXT

  classDef pub fill:#d9772a,stroke:#a95712,color:#fff;
  classDef aux fill:#f7e2cf,stroke:#d9772a,color:#1a1f29;
  classDef pure fill:#fff,stroke:#d9772a,color:#a95712;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

## 4. `cicflowmeter.py` + l'étiquetage de `datasets.py` — pcap → flux étiquetés

```mermaid
flowchart TD
  subgraph CFM["cicflowmeter.py"]
    tar["_tar_bytes()"]:::pure
    split["split_pcap()"]:::pure
    windowed["windowed_flows_csv()"]:::pure
    relabel["relabel_csv()"]:::pure
    parseTs["parse_timestamp()"]:::pure
    subgraph FW["class FlowMeterWorker"]
      fInit["__init__()"]:::aux
      convert["convert()"]:::pub
      fClose["close()"]:::pub
    end
  end

  subgraph DSLBL["datasets.py (étiquetage)"]
    labelDs["label_dataset_csv() → label_of()"]:::pure
    matches["AttackRun.matches()"]:::pure
  end

  cfmImg(["conteneur CICFlowMeter"]):::ext

  windowed --> fInit
  windowed --> split
  windowed --> convert
  windowed --> fClose
  convert --> tar
  convert --> cfmImg
  labelDs --> relabel
  labelDs --> matches
  labelDs --> parseTs

  classDef pub fill:#3a9bb0,stroke:#277585,color:#fff;
  classDef aux fill:#d6edf2,stroke:#3a9bb0,color:#1a1f29;
  classDef pure fill:#fff,stroke:#3a9bb0,color:#277585;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

## 5. `datasets.py` — génération d'un dataset (tâche de fond)

```mermaid
flowchart TD
  subgraph DS["datasets.py"]
    labelDs["label_dataset_csv()"]:::pure
    failW["failure_warning()"]:::pure
    makeVar["make_variant()"]:::pure
    remove["_remove()"]:::pure
    matches["AttackRun.matches()"]:::pure
    subgraph DB["class DatasetBuilder"]
      prepare["prepare()"]:::pub
      run["run()"]:::pub
      generate["_generate()"]:::aux
      play["_play()"]:::aux
      meta["_meta()"]:::aux
    end
    subgraph DSS["class DatasetStore (hérite RecordStore)"]
      dsInit["__init__()"]:::aux
    end
  end

  trafEXT["traffic.* (require_device, name_of, device_ip,<br/>primary_interface, start_benign, stop_benign, extract_file)"]:::ext
  labEXT["lab.start_netns_helper"]:::ext
  jobEXT["job.sleep / step / warn"]:::ext
  cfmEXT["cicflowmeter.windowed_flows_csv"]:::ext
  storeEXT["store.new_id / save"]:::ext

  prepare --> trafEXT
  run --> makeVar
  run --> generate
  generate --> trafEXT
  generate --> labEXT
  generate --> jobEXT
  generate --> play
  generate --> failW
  generate --> cfmEXT
  generate --> labelDs
  generate --> meta
  generate --> storeEXT
  generate --> remove
  play --> trafEXT
  play --> labEXT
  play --> jobEXT
  play --> remove
  labelDs --> matches

  classDef pub fill:#2fa36a,stroke:#1d7a4d,color:#fff;
  classDef aux fill:#d3efe0,stroke:#2fa36a,color:#1a1f29;
  classDef pure fill:#fff,stroke:#2fa36a,color:#1d7a4d;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

## 6. `training.py` — entraînement du Random Forest (tâche de fond)

```mermaid
flowchart TD
  subgraph TR["training.py"]
    loadFr["load_frames()"]:::pure
    targets["targets()"]:::pure
    featMat["feature_matrix()"]:::pure
    dropC["drop_constant()"]:::pure
    evaluate["evaluate()"]:::pure
    byAtk["by_attack()"]:::pure
    counts["_counts()"]:::pure
    subgraph TRN["class Trainer"]
      tPrep["prepare()"]:::pub
      tRun["run()"]:::pub
    end
    subgraph MS["class ModelStore (hérite RecordStore)"]
      mInit["__init__()"]:::aux
    end
  end

  storeEXT["store.file_path / new_id / save"]:::ext
  sklEXT(["sklearn: RandomForest.fit,<br/>predict, compute_sample_weight + joblib"]):::ext

  tRun --> loadFr
  tRun --> targets
  tRun --> featMat
  tRun --> dropC
  tRun --> evaluate
  tRun --> byAtk
  tRun --> counts
  tRun --> sklEXT
  tRun --> storeEXT
  loadFr --> storeEXT

  classDef pub fill:#7b53d6,stroke:#5a37a8,color:#fff;
  classDef aux fill:#e4dbf7,stroke:#7b53d6,color:#1a1f29;
  classDef pure fill:#fff,stroke:#7b53d6,color:#5a37a8;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

## 7. `detection.py` — détection en direct (session + boucle)

```mermaid
flowchart TD
  subgraph DET["detection.py"]
    outcome["outcome_of()"]:::pure
    subgraph DM["class DetectionManager"]
      start["start()"]:::pub
      stop["stop()"]:::pub
      reset["reset()"]:::pub
      status["status()"]:::pub
      shown["_shown_events()"]:::aux
      loop["_loop()"]:::aux
      tick["_tick()"]:::aux
      classify["_classify()"]:::aux
      knownAtk["_known_attacks()"]:::aux
      benIps["_benign_ips()"]:::aux
      cleanup["_cleanup()"]:::aux
    end
  end

  trafEXT["traffic.* (require_device, name_of,<br/>device_ip, primary_interface, extract_file)"]:::ext
  labEXT["lab.start_netns_helper / helpers / find_device"]:::ext
  modEXT["models.get / file_path (joblib.load)"]:::ext
  cfmEXT["cicflowmeter.FlowMeterWorker.convert/close + parse_timestamp"]:::ext
  trainEXT["training.feature_matrix"]:::ext
  trafInfo["traffic.docker_time"]:::ext
  sklEXT(["model.predict / predict_proba"]):::ext

  start --> stop
  start --> trafEXT & modEXT & labEXT
  start --> loop
  start --> status
  stop --> cleanup
  status --> shown
  loop --> tick
  tick --> trafEXT
  tick --> cfmEXT
  tick --> classify
  classify --> trainEXT
  classify --> sklEXT
  classify --> knownAtk
  classify --> benIps
  classify --> outcome
  classify --> cfmEXT
  knownAtk --> labEXT & trafEXT & trafInfo
  benIps --> labEXT & trafEXT
  cleanup --> cfmEXT
  cleanup --> labEXT

  classDef pub fill:#d8465c,stroke:#a62d41,color:#fff;
  classDef aux fill:#f6d6dc,stroke:#d8465c,color:#1a1f29;
  classDef pure fill:#fff,stroke:#d8465c,color:#a62d41;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

## 8. `jobs.py` + `store.py` — briques transverses

```mermaid
flowchart TD
  subgraph JOBS["jobs.py"]
    subgraph JOB["class Job"]
      jBegin["begin()"]:::aux
      jStep["step()"]:::aux
      jWarn["warn()"]:::aux
      jCancel["cancel()"]:::aux
      jSleep["sleep()"]:::aux
      jCheck["check_cancelled()"]:::aux
      jRun["run(work)"]:::pub
      jDict["to_dict()"]:::pub
    end
    subgraph JR["class JobRegistry"]
      jrStart["start()"]:::pub
      jrCurrent["current()"]:::pub
      jrGet["get()"]:::pub
    end
  end

  workEXT["work = DatasetBuilder.run / Trainer.run"]:::ext

  jrStart --> jrCurrent
  jrStart --> jRun
  jRun --> workEXT

  subgraph STORE["store.py"]
    subgraph RS["class RecordStore"]
      sDir["_dir()"]:::aux
      sNew["new_id()"]:::pub
      sSave["save()"]:::pub
      sList["list()"]:::pub
      sGet["get()"]:::pub
      sFile["file_path()"]:::pub
      sDel["delete()"]:::pub
    end
    idre["ID_RE (regex)"]:::pure
  end

  sDir --> idre
  sGet --> sDir
  sFile --> sDir
  sDel --> sDir

  classDef pub fill:#5b6472,stroke:#3b4250,color:#fff;
  classDef aux fill:#e2e5ea,stroke:#5b6472,color:#1a1f29;
  classDef pure fill:#fff,stroke:#5b6472,color:#3b4250;
  classDef ext fill:#eef1f6,stroke:#9aa3b2,color:#1a1f29;
```

---

### Note

`store.py` expose `RecordStore` ; `DatasetStore` (`datasets.py`) et `ModelStore` (`training.py`)
en héritent — donc `datasets.save/new_id/...` et `models.save/file_path/...` sont en fait les
méthodes de `RecordStore` ci-dessus. Les classes de données (`BenignSource`, `AttackRun`,
`DatasetPlan`, `TrainingPlan`, `Session`) et les modèles Pydantic de `main.py`
(`StartRequest`, `Target`, `BenignRequest`, …) ne sont pas des fonctions : elles ne portent que
des champs (sauf `AttackRun.matches` et `Job.to_dict`, inclus ci-dessus).

Ordre de lecture conseillé du code : `settings → store → jobs → lab → traffic → cicflowmeter → datasets → training → detection → main`.
