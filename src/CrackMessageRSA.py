import linecache
import LogicielRSA

def find_contact(auteur, destinataire):
    """Str x Str --> Tuple
    Retourne les lignes ou se trouve le nom de l'auteur et du destinataire entrés dans l'annuaire"""
    annuaire = open("../res/annuaire.txt", "r")
    datafile = annuaire.readlines()
    ligne = 0
    la, ld = False, False
    for line in datafile:
        ligne +=1
        if auteur == line[:-1]:
            la = ligne
        if destinataire == line[:-1]:
            ld = ligne
    annuaire.close()
    if la == False or ld ==False:
        print("Cet auteur ou ce destinataire n'existe pas")
    return (la, ld)

def find_n(lignes):
    """Tuple --> Tuple
    Retourne les n de l'auteur et du destinataire"""
    annuaire = open("../res/annuaire.txt", "r")
    line = annuaire.readlines()
    ligne_na = lignes[0] + 2
    ligne_nd = lignes[1] + 2
    na = int(linecache.getline('../res/annuaire.txt', ligne_na)[:-1])
    nb = int(linecache.getline('../res/annuaire.txt', ligne_nd)[:-1])
    annuaire.close()
    return na,nb

def find_clepubl(lignes):
    """Tuple --> Tuple
    Retourne les clé publiques de l'auteur et du destinataire"""
    annuaire = open("annuaire.txt", "r")
    line = annuaire.readlines()
    ligne_ea = lignes[0] + 1
    ligne_ed = lignes[1] + 1
    ea = int(linecache.getline('../res/annuaire.txt', ligne_ea)[:-1])
    ed = int(linecache.getline('../res/annuaire.txt', ligne_ed)[:-1])
    annuaire.close()
    return ea, ed

def BobCrack(fichier, alice, dB, nB,s, v):
    """str x str x int x int -> str
    Decode un fichier et renvoie le nom du fichier decodé"""
    annuaire = open("../res/annuaire.txt", "r")
    annuairePriv = open("../res/annuairePriv.txt", "r")
    l = []
    for line in annuaire:
        if line[-1] == "\n":
            l.append(line[:-1])
        else:
            l.append(line)
    for a in l:
        if a == alice:
            u = l.index(a)
            dA = int(l[u + 1])
            nA = int(l[u + 2])
            break
    nom_Fichier = "../message/"+fichier+".txt"
    nom_Fichier_deux = "../message/"+fichier + "decrypte.txt"
    fichier = open(nom_Fichier, "r+")
    fichier2 = open(nom_Fichier_deux, "w")
    la = []
    for line in fichier:
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
    fichier.close()
    fichier2.close()
    annuaire.close()
    return nom_Fichier_deux
