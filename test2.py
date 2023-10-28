import re
import hashlib
import bcrypt
import dic


# Fonction pour valider un email
def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email)

# Fonction pour valider un mot de passe
def is_valid_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$!%^&*])[A-Za-z\d@#$!%^&*]{8,}$', password))

# Fonction pour enregistrer un utilisateur
def enregistrer_utilisateur(email, password):
    with open('Enregistrement.txt', 'a') as file:
        file.write(f'{email}:{password}\n')

# Fonction pour authentifier un utilisateur
def authentifier_utilisateur(email, password):
    with open('Enregistrement.txt', 'r') as file:
        for line in file:
            stored_email, stored_password = line.strip().split(':')
            if email == stored_email and bcrypt.checkpw(password.encode(), stored_password.encode()):
                return True
    return False


def charger_dictionnaire_de_fichier(nom_fichier):
    dictionnaire = {}
    with open('dic.txt', 'r') as file:
        for line in file:
            mot = line.strip()
            hachage = hashlib.sha256(mot.encode()).hexdigest()
            dictionnaire[mot] = hachage
    return dictionnaire

# Charger le dictionnaire depuis le fichier
nom_fichier_dictionnaire = "dic.txt"  # Remplacez par le nom de votre fichier
dictionnaire_de_mots = charger_dictionnaire_de_fichier(nom_fichier_dictionnaire)

while True:
    print("1. Enregistrement")
    print("2. Authentification")
    choix = input("Choisissez une option (1/2) : ")

    if choix == '1':
        email = input("Entrez votre email : ")
        if is_valid_email(email):
            password = input("Entrez votre mot de passe : ")
            if is_valid_password(password):
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                enregistrer_utilisateur(email, hashed_password.decode())
                print("Utilisateur enregistré avec succès.")
            else:
                print("Le mot de passe n'est pas valide.")
        else:
            print("L'email n'est pas valide.")

    elif choix == '2':
        email = input("Entrez votre email : ")
        password = input("Entrez votre mot de passe : ")
        if authentifier_utilisateur(email, password):
            print("Authentification réussie.")
            while True:
                print("Menu de l'utilisateur authentifié:")
                print("a. Hachez le mot par sha256")
                print("b. Hachez le mot en générant un salt (bcrypt)")
                print("c. Attaquer par Dictionnaire le Mot inséré")
                print("q. Quitter")
                choix_utilisateur = input("Choisissez une option (a/b/c/q) : ")
                if choix_utilisateur == 'a':
                    mot_a_hacher = input("Donnez un mot à hacher : ")
                    hashed = hashlib.sha256(mot_a_hacher.encode()).hexdigest()
                    print(f"Mot haché avec SHA-256 : {hashed}")
                elif choix_utilisateur == 'b':
                    mot_a_hacher = input("Donnez un mot à hacher : ")
                    salt = bcrypt.gensalt()
                    hashed = bcrypt.hashpw(mot_a_hacher.encode(), salt)
                    print(f"Mot haché avec bcrypt : {hashed.decode()}")
                elif choix_utilisateur == 'c':
                    mot_a_hacher = input("Donnez un mot à hacher : ")
                    if mot_a_hacher in dictionnaire_de_mots:
                        hashed = dictionnaire_de_mots[mot_a_hacher]
                        print(f"Mot haché avec le dictionnaire : {hashed}")
                    else:
                        print("Mot non trouvé dans le dictionnaire.")