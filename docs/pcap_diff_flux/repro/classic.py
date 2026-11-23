# Force brute "classique" : un login rate nu (comme hydra/ftp-patator). UNE connexion.
import ftplib
ftp = ftplib.FTP()
ftp.connect("127.0.0.1", 2121, timeout=10)
try:
    ftp.login("duhan", "123456")      # mauvais mdp -> 530
except ftplib.error_perm:
    pass
try: ftp.quit()
except Exception: pass
