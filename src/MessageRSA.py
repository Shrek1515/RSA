import LogicielRSA
import CrackMessageRSA as CMRSA
from pathlib import Path

##################### FONCTIONS ############

def Annuaire(nom,niveau):
    """str -> int x int x int
    permet d'inscrire une personne dans un annuaire et lui renvoie ses coordonnées privées et publiques
    seules les coordonnées publique sont inscrites dans l'annuaire"""
    repertoire_courant = Path(__file__).parent
    chemin_public = repertoire_courant.parent/'res'/'annuaire.txt'
    chemin_prive = repertoire_courant.parent/'res'/'annuairePriv.txt'
    annuaire = open(chemin_public, "a")
    annuairePriv = open(chemin_prive, "a")
    if niveau.lower() == "f":
        n = 20
    elif niveau.lower() == "m":
        n = 40
    elif niveau.lower() == "d":
        n = 70
    p, q = LogicielRSA.premiers_aleatoires(n), LogicielRSA.premiers_aleatoires(n)     #Parametre de la fonction à baisser pour utiliser CrackMessageRSA
    e, d, n = LogicielRSA.generateurCle(p, q)
    annuaire.write(nom+"\n")
    annuairePriv.write(nom + "\n")
    annuaire.write(str(e)+"\n")
    annuairePriv.write(str(d) + "\n")
    annuaire.write(str(n)+"\n")
    annuairePriv.write(str(n) + "\n")
    annuaire.write("\n")
    annuairePriv.write("\n")
    annuaire.close()
    annuairePriv.close()
    return "clé privée = ", d, "clé publique = ", e, "n = ",n

def Alice(alice, fichier, bob, s):
    """str x str x str x int x int -> str
    Code un fichier avec une signature, renvoie le nom du fichier codé"""
    repertoire_courant = Path(__file__).parent
    chemin_public = repertoire_courant.parent/'res'/'annuaire.txt'
    chemin_prive = repertoire_courant.parent/'res'/'annuairePriv.txt'
    annuaire = open(chemin_public, "r")
    annuairePriv = open(chemin_prive, "r")
    l = []
    for line in annuaire :
        if line[-1] == "\n":
            l.append(line[:-1])
        else:
            l.append(line)
    lPriv = []
    for line in annuairePriv:
        if line[-1] == "\n":
            lPriv.append(line[:-1])
        else:
            lPriv.append(line)
    for a in l:
        if a == bob:
            u = l.index(a)
            eB = int(l[u+1])
            nB = int(l[u+2])
            break
    for a in lPriv:
        if a == alice:
            u = lPriv.index(a)
            dA = int(lPriv[u+1])
            nA = int(lPriv[u+2])
            break
    nom_Fichier = repertoire_courant.parent/'message'/f"{fichier}.txt"
    fichier1 = open(nom_Fichier, "r")
    nom_Fichier2 = repertoire_courant.parent/'message'/f"{fichier}_Code.txt"
    fichier2 = open(nom_Fichier2, "w")
    la = []
    for line in fichier1:
        if line[-1] == "\n":
            la.append(line[:-1])
        else:
            la.append(line)
    for a in la:
        c = LogicielRSA.codage_ascii_triplet(a, eB, nB)
        for e in c:
            fichier2.write(e+" ")
        fichier2.write("\n")
    if s:
        fichier2.write("signature\n")
        signature = "Je suis "+alice
        signature = LogicielRSA.codage_ascii_triplet(signature, dA, nA)
        for a in signature:
            fichier2.write(a+" ")
    fichier1.close()
    fichier2.close()
    annuaire.close()
    annuairePriv.close()
    return f"{fichier}_Code.txt"

def Bob(fichier, alice, bob, s, v):
    """str x str x int x int -> str
    Decode un fichier et renvoie le nom du fichier decodé"""
    #annuaire = open("../res/annuaire.txt", "r")
    #annuairePriv = open("../res/annuairePriv.txt", "r")
    repertoire_courant = Path(__file__).parent
    chemin_public = repertoire_courant.parent/'res'/'annuaire.txt'
    chemin_prive = repertoire_courant.parent/'res'/'annuairePriv.txt'
    annuaire = open(chemin_public, "r")
    annuairePriv = open(chemin_prive, "r")
    l = []
    for line in annuaire:
        if line[-1] == "\n":
            l.append(line[:-1])
        else:
            l.append(line)
    lPriv = []
    for line in annuairePriv:
        if line[-1] == "\n":
            lPriv.append(line[:-1])
        else:
            lPriv.append(line)
    for a in l:
        if a == alice:
            u = l.index(a)
            dA = int(l[u + 1])
            nA = int(l[u + 2])
            break
    for a in lPriv:
        if a == bob:
            u = lPriv.index(a)
            dB = int(lPriv[u + 1])
            nB = int(l[u + 2])
            break
    #nom_Fichier = "../message/"+fichier+".txt"
    #nom_Fichier_deux = "../message/"+fichier + "decrypte.txt"

    nom_Fichier = repertoire_courant.parent/'message'/f"{fichier}.txt"
    nom_Fichier_deux = repertoire_courant.parent/'message'/f"{fichier}decrypte.txt"

    fichier1 = open(nom_Fichier, "r+")
    fichier2 = open(nom_Fichier_deux, "w")
    la = []
    for line in fichier1:
        if line[-1] == "\n":
            la.append(line[:-1])
        else:
            la.append(line)
    if s == True:
        s1 = la.index("signature")
        for a in la[:s1]:
            lb = a.split(" ")
            if lb[-1] == "":
                lb = lb[:-1]
            c = LogicielRSA.decodage_ascii_triplet(lb, dB, nB)
            fichier2.write(c + "\n")
        fichier2.write("\nsignature" + "\n")
        signature = la[s1 + 1]
        signature = signature.split(" ")
        signature = signature[:-1]
        c = LogicielRSA.decodage_ascii_triplet(signature, dA, nA)
        fichier2.write(c)
    else:
        if v == True:
            s1 = la.index("signature")
            for a in la[:s1]:
                lb = a.split(" ")
                if lb[-1] == "":
                    lb = lb[:-1]
                c = LogicielRSA.decodage_ascii_triplet(lb, dB, nB)
                fichier2.write(c + "\n")
        else:
            for a in la:
                lb = a.split(" ")
                if lb[-1] == "":
                    lb = lb[:-1]
                c = LogicielRSA.decodage_ascii_triplet(lb, dB, nB)
                fichier2.write(c + "\n")
    fichier1.close()
    fichier2.close()
    annuaire.close()
    annuairePriv.close()
    return f"{fichier}decrypte.txt"

##################### EXECUTION ############

def main():
    saisie = "oui"

    while saisie != "s":
        s = False
        v = False
        saisie = input("Que voulez-vous faire ? Inscription (i) - Envoi (e) - Reception (r) - craquer (c) - stop (s) : ")
        if saisie.lower() == "i":
            nom = input("Entrez votre nom : ")
            niveau = input("Choisissez votre niveau de sécurité: facile (f) - moyen (m) - difficile (d) : ")
            print(" Info sur le contact : ", Annuaire(nom, niveau))
        elif saisie.lower() == "e":
            alice = input("Entrez votre nom : ")
            bob = input("Entrez le destinataire : ")
            fichier = input("Entrez le nom du fichier à coder : ")
            sn = input("Voulez-vous ajouter une signature ? oui - non : ")
            if sn.lower() == "oui": s = True
            print("voici le nom du fichier crypté : ", Alice(alice, fichier, bob, s))
        elif saisie.lower() == "r":
            bob = input("Entrez votre nom : ")
            alice = input("Entrez le nom de l'envoyeur : ")
            fichier = input("Entrez le nom du fichier à decoder : ")
            repertoire_courant = Path(__file__).parent
            #nom_Fichier = "../message/"+fichier + ".txt"
            nom_Fichier = repertoire_courant.parent/'message'/f"{fichier}.txt"
            fichier1 = open(nom_Fichier, "r")
            la = []
            for line in fichier1:
                if line[-1] == "\n":
                    la.append(line[:-1])
                else:
                    la.append(line)
            if "signature" in la:
                v = True
                sn = input("Voulez-vous décoder la signature ? oui - non : ")
                if sn.lower() == "oui":
                    s = True
            print("Voici le nom du fichier decrypté : ", Bob(fichier, alice, bob, s, v))
        elif saisie.lower() == "c":
            auteur = input("Entrez l'auteur du message que vous voulez décoder : ")
            destinataire = input("Entrez le destinataire : ")
            fichier = input("Entrez le nom du fichier à decoder : ")
            tmp = int(input("Combien de temps en seconde voulez-vous alouer au cassage de la clé ? "))
            contacts = CMRSA.find_contact(auteur, destinataire)
            n = CMRSA.find_n(contacts)
            e = CMRSA.find_clepubl(contacts)
            pa = LogicielRSA.rho_pollard(n[0], tmp)
            pd = LogicielRSA.rho_pollard(n[1], tmp)
            da = False
            dd = False
            if type(pa) == str:
                print("la clé privée de l'auteur est trop longue pour être cassée")
            else:
                qa = (n[0]) // pa
                da = LogicielRSA.generateur_cassage(pa, qa, e[0])
                print("Le n de l'auteur: ", n[0], "Clé publique de l'auteur: ", e[0], "Clé privée de l'auteur : ", da)
            if type(pd) == str:
                print("la clé privée du destinataire est trop longue pour être cassée")
            else:
                qd = (n[1]) // pd
                dd = LogicielRSA.generateur_cassage(pd, qd, e[1])
                print("Le n du destinataire: ", n[1], "Clé publique du destinataire: ", e[1], "Clé privée du destinataire : ", dd)
            if da != False and dd != False:
                s = False
                la = []
                nom_Fichier = "../message/"+fichier + ".txt"
                fichier1 = open(nom_Fichier, "r")
                for line in fichier1:
                    if line[-1] == "\n":
                        la.append(line[:-1])
                    else:
                        la.append(line)
                if "signature" in la:
                    v = True
                    sn = input("Voulez-vous décoder la signature ? oui - non : ")
                    if sn.lower() == "oui":
                        s = True
                print("Voici le nom du fichier decrypté : ", CMRSA.BobCrack(fichier, auteur, dd, n[1], s, v))