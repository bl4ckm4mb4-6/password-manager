import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import sqlite3
import os
import getpass

path_salt = os.path.join("files", "salt.bin")
path_db = os.path.join("files", "manager_pw.db")

def genera_salt():
    salt = os.urandom(16)
    with open(path_salt, "wb") as file:
        file.write(salt)

def recupera_salt():
    try:
        with open(path_salt, "rb") as file:
            salt = file.read()
        return salt
    except FileNotFoundError as fnf:
        print(f"\nFile salt.bin non esistente! {fnf}")
        exit(1)

# Operazioni su database
def inizializza_db():
    # Si connette al db. Se non esiste lo crea
    conn = sqlite3.connect(path_db)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credenziali(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   servizio TEXT NOT NULL,
                   username TEXT NOT NULL,
                   password BLOB NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def salva_password(servizio, username, password):
    conn = sqlite3.connect(path_db)
    cursor = conn.cursor()

    # Uso "?" per evitare SQL Injection
    cursor.execute('''
        INSERT INTO credenziali (servizio, username, password)
        VALUES (?, ?, ?)
    ''', (servizio, username, password))
    
    conn.commit()
    conn.close()
    print(f"\nPassword per {servizio} salvata correttamente!")

def recupera_tutto():
    conn = sqlite3.connect(path_db)
    cursor = conn.cursor()
    
    cursor.execute("SELECT servizio, username, password FROM credenziali")
    risultati = cursor.fetchall()
    
    conn.close()
    return risultati

def recupera_password_servizio(servizio):
    conn = sqlite3.connect(path_db)
    cursor = conn.cursor()

    cursor.execute("SELECT servizio, username, password FROM credenziali WHERE servizio = ?", (servizio,))
    risultato = cursor.fetchone()

    conn.close()
    return risultato

def elimina_servizio(servizio):
    conn = sqlite3.connect(path_db)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM credenziali WHERE servizio = ?", (servizio,))
    if cursor.fetchone() is None:
        print(f"\nErrore: servizio inesistente [{servizio}]")
    else:
        cursor.execute("DELETE FROM credenziali WHERE servizio = ?", (servizio,))
        conn.commit()
        print(f"\nCredenziali servizio eliminate con successo! [{servizio}]")
    
    conn.close()

def elimina_tutto():
    conn = sqlite3.connect(path_db)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM credenziali")
    conn.commit()
    conn.close()
    print("\nEliminazione totale andata a buon fine!")

def recupera_primo_servizio():
    conn = sqlite3.connect(path_db)
    cursor = conn.cursor()

    cursor.execute("SELECT servizio, username, password FROM credenziali LIMIT 1")
    risultato = cursor.fetchone()

    conn.close()
    return risultato

# Funzioni per crittografia
def genera_chiave_fernet(master_pw):
    salt = recupera_salt()
    master_pw_byte = master_pw.encode()

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000, # Più è alto, più è sicuro (ma più lento)
    )

    chiave = base64.urlsafe_b64encode(kdf.derive(master_pw_byte))
    return chiave

def crittografa(chiave, servizio, username, password):
    f = Fernet(chiave)

    password_cifrata = f.encrypt(password.encode())
    print("\nPassword crittografata con successo")
    salva_password(servizio, username, password_cifrata)

def decrittografa(chiave, password_cifrata_db):
    f = Fernet(chiave)

    password_decifrata = f.decrypt(password_cifrata_db).decode()
    return password_decifrata


# MAIN

# Controllo se esiste la cartella files
if not os.path.exists("files"):
    os.makedirs("files")

# Controllo se esistono i file
if not os.path.exists(path_db):
    inizializza_db()
if not os.path.exists(path_salt):
    genera_salt()

print("\nLa master password DEVE essere la stessa per tutti i servizi!\n")
# Creo un menu' interattivo
while True:
    print("\n-----MENU-----\n1) Inserisci nuove credenziali\n" \
        "2) Visualizza credenziali di un servizio\n" \
        "3) Visualizza credenziali di tutti i servizi\n" \
        "4) Elimina un servizio\n" \
        "5) Elimina tutto\n" \
        "6) Exit")

    while True:
        scelta = int(input("Scegli voce dal menu': "))
        if scelta < 1  or scelta > 6:
            print("Valore non ammesso\n")
            pass
        else:
            break

    match(scelta):
        case 1:
            servizio = input("Inserisci servizio: ")
            username = input("Inserisci username: ")
            pw = input("Inserisci password: ")
            master_pw = getpass.getpass("Inserisci master password per crittografare: ")
            chiave = genera_chiave_fernet(master_pw)
            crittografa(chiave, servizio, username, pw)

        case 2:
            servizio = input("Inserisci servizio da recuperare: ")
            master_pw = getpass.getpass("Inserisci master password per decrittografare: ")
            chiave = genera_chiave_fernet(master_pw)
            risultato = recupera_password_servizio(servizio)

            if not risultato:
                print("\nServizio inesistente\n")
            else:
                try:
                    pw = decrittografa(chiave, risultato[2])
                    print(f"\nServizio: {risultato[0]}\n" \
                        f"Username: {risultato[1]}\n" \
                        f"Password: {pw}\n")
                except:
                    print("\nMaster password errata!\n")

        case 3:
            master_pw = getpass.getpass("Inserisci master password per decrittografare: ")
            chiave = genera_chiave_fernet(master_pw)
            risultato = recupera_tutto()

            if not risultato:
                print("\nIl database e' vuoto\n")
            else:
                for servizio, username, pw_cifrata in risultato:
                    try:
                        pw_decifrata = decrittografa(chiave, pw_cifrata)
                        print(f"\nServizio: {servizio}\n" \
                        f"Username: {username}\n" \
                        f"Password: {pw_decifrata}\n")
                    except:
                        print("\nMaster password errata!\n")

        case 4:
            servizio = input("Inserisci servizio da eliminare: ")
            credenziali = recupera_password_servizio(servizio)
            
            if not credenziali:
                print("\nServizio inesistente")
            else:
                master_pw = getpass.getpass("Inserisci master password per eliminare servizio: ")
                chiave = genera_chiave_fernet(master_pw)
                try:
                    pw = decrittografa(chiave, credenziali[2])
                    elimina_servizio(servizio)
                except:
                    print("\nMaster password errata! Operazione annullata")

        case 5:
            conferma = input("Sei sicuro di eliminare tutte le credenziali? (si/no): ")
            if conferma.lower() == "si":
                risultato = recupera_primo_servizio()

                if not risultato:
                    print("\nDatabase gia' vuoto")
                else:
                    master_pw = getpass.getpass("Inserisci master password per eliminare tutto: ")
                    chiave = genera_chiave_fernet(master_pw)
                    try:
                        pw = decrittografa(chiave, risultato[2])
                        elimina_tutto()
                    except:
                        print("\nMaster password errata! Operazione annullata")
            else:
                print("\nOperazione annullata")

        case 6:
            exit(0)