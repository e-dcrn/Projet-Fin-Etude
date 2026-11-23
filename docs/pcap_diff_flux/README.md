# Diff pcap d'un flux : force brute FTP classique vs furtive

Deux captures réseau réelles d'**un seul flux** chacune, pour le même essai de mot de passe
(`duhan` / `123456`, rejeté par le serveur). Même cœur d'attaque, deux formes de flux opposées.
Ouvre-les dans Wireshark :

- [`flux_classique.pcap`](flux_classique.pcap) — un login raté « nu » (ce qu'émet `ftp-patator` / hydra).
- [`flux_furtif.pcap`](flux_furtif.pcap) — le même essai, « habillé » par le script d'évasion.

> Ce ne sont pas des schémas : ce sont de **vrais paquets** capturés au niveau TCP. Les traces
> ci-dessous sont la sortie de `tshark`, le diff est un `diff` de ces deux traces.

---

## Mesuré sur les deux flux

| Grandeur (par flux)                | 🔴 Classique | 🟢 Furtif | Rapport |
| ---------------------------------- | -----------: | --------: | ------: |
| Trames TCP                         |         17   |      70   |  ×4,1   |
| Octets applicatifs (payload)       |      134 o   |  4 328 o  |  **×32**|
| Octets totaux (avec en-têtes)      |    1 272 o   |  8 964 o  |  ×7,0   |
| Taille moyenne de trame            |     74,8 o   |  128,1 o  |  ×1,7   |

Le modèle décide **par flux**, surtout sur des **tailles de paquet** et le **volume d'octets**
(`Packet Length Mean`, `Average Packet Size`, `Flow Bytes/s`). Le flux classique est un flux
**pauvre** (134 o) → zone « attaque ». Le flux furtif échange **32× plus d'octets applicatifs** →
il tombe dans la zone « session normale ». L'attaque n'a ni changé d'outil ni ralenti : elle a
changé la **forme** du flux.

---

## Le diff (niveau commande FTP)

Le cœur de l'attaque — `USER duhan` → `331` → `PASS 123456` → `530` — est **identique** dans les
deux flux (lignes alignées au centre). Tout ce qui est marqué `>` est le **bourrage** ajouté par
l'attaque furtive : des `NOOP` portant une grande ligne d'arguments (beaucoup d'octets *vers* le
serveur) et des `HELP` / `FEAT` qui déclenchent de longues réponses (octets *de retour*).

```
flux CLASSIQUE                              flux FURTIF
<-- 220  IDS-Lab demo FTP ready             <-- 220  IDS-Lab demo FTP ready
                                          > --> NOOP la session consulte… (260 o)
                                          > <-- 501  Syntax error…
                                          > --> NOOP la session consulte… (172 o)
                                          > <-- 501  Syntax error…
                                          > --> HELP
                                          > <-- 214  The following commands…
                                          > <-- 214  Help command successful.
                                          > --> NOOP la session consulte… (167 o)
                                          > <-- 501  Syntax error…
                                          > --> HELP SITE
                                          > <-- 214  Syntax: SITE…
--> USER   duhan                      ===   --> USER   duhan
<-- 331    Username ok, send password ===   <-- 331    Username ok, send password
--> PASS   123456                     ===   --> PASS   123456
<-- 530    Authentication failed.     ===   <-- 530    Authentication failed.
--> QUIT                                   > --> NOOP la session consulte… (123 o)
<-- 221    Goodbye.                        > <-- 501  Syntax error…
                                          > --> NOOP la session consulte… (336 o)
                                          > … (HELP, FEAT, NOOP jusqu'à ~440 o) …
```

Diff complet et traces brutes : [`diff_cote_a_cote.txt`](diff_cote_a_cote.txt),
[`trace_classique.txt`](trace_classique.txt), [`trace_furtif.txt`](trace_furtif.txt).

> **Lecture.** Les 4 lignes alignées (`===`) sont l'attaque réelle, bit pour bit la même. Le
> furtif ne « cache » pas l'essai de mot de passe : il le **noie** dans assez de vrai trafic FTP
> pour que la fiche de statistiques du flux ressemble à celle d'une session bénigne.

---

## Reproduire

Capture locale, 100 % reproductible, sans la pile Docker du lab (voir [`repro/`](repro/)) :

1. serveur FTP local (`pyftpdlib`) sur `127.0.0.1:2121` ;
2. capture de `lo` (port 2121) ;
3. `classic.py` (un login raté nu) puis `stealth.py` (le vrai script `_FTP_STEALTH` du projet,
   [`code/backend/app/traffic.py`](../../code/backend/app/traffic.py), adapté au port local).

```bash
python3 -m venv venv && ./venv/bin/pip install pyftpdlib
bash repro/run.sh      # produit capture.pcap ; filtrer par tcp.stream pour isoler chaque flux
```

> **Fidélité.** Le mécanisme (gros `NOOP` + réponses longues qui gonflent le flux) est exactement
> celui du script de production. Le serveur `pyftpdlib` refuse les arguments de `NOOP` (réponse
> `501` courte) là où un vrai serveur FTP renverrait plus d'octets : l'écart de volume mesuré ici
> (×32 sur le payload) est donc un **minorant** de celui obtenu dans le lab complet, où le rapport
> d'évasion mesure la détection chuter de ~87 % à ~9 % (`code/docs/rapports/rapport_evasion.md`).
