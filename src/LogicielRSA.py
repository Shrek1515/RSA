import random
import math
import time

def miller_rabin(n, k=20):
  """ en entree : n l'entier a tester
                          k le compteur
      en sortie: un booleen (True si premier)"""
  if n == 2 or n == 3:
    return True
  if n % 2 == 0:
    return False
  r, s = 0, n - 1
  while s % 2 == 0:
    r += 1
    s //= 2  # la partie non paire de n-1 / permet la factorisation en nombre premier
  for _ in range(k):
    a = random.randrange(2, n - 1)
    x = pow(a, s, n)
    if x == 1 or x == n - 1:
      continue
    for _ in range(r - 1):
      x = pow(x, 2, n)
      if x == n - 1:
        break
    else:
      return False
  return True

def premiers_aleatoires(n_bits):
  """ Int --> Int
  Genere un nombre pseudo-aléatoire de n bits (càd que sa representation binaire comporte n chiffres)"""
  p = random.getrandbits(n_bits)
  while not miller_rabin(p):
    p = random.getrandbits(n_bits)
  return p

def bezout(a, b):
  """int x int -> int retourne v tel que au+bv=1 pour a = e et b = PhiN donnés"""
  r, u, v, r1, u1, v1 = a, 1, 0, b, 0, 1
  while r1 != 0:
    q = r // r1
    r, u, v, r1, u1, v1 = r1, u1, v1, r - q * r1, u - q * u1, v - q * v1
  return v

def generateurCle(p, q):
  """Int x Int ---> Int x Int x Int
  Génère une clé privée et publique avec p et q"""
  n = p * q
  PN = (p - 1) * (q - 1)
  e = random.randint(2, PN - 1)
  while math.gcd(PN, e) != 1:
    e = random.randint(2, PN - 1)
  d = bezout(PN, e)
  if d < 0 :
    d = d + PN
  return e, d, n

def exprapide(a, exp, n):
  """Int x Int x Int --> Int
  Exponentiation rapide"""
  p = 1
  while exp > 0:
    if exp % 2 == 0:
      p = (p * a) % n
    a = (a * a) % n
    exp = exp // 2
  return p

def codage_ascii_triplet(caractere, e, n):
  """ String x Int x Int --> List
  Prend en parametre une chaine de caractere et la clé publique (formée de e et n) et forme une liste
  des valeurs ASCII de chaque caractere, étant regroupé par triplets. Retourne une liste de valeurs ASCII chiffrés. """
  ascii_simple = [str(ord(lettres)) for lettres in caractere]
  for i, k in enumerate(ascii_simple):
    while len(k) < 3:
      k = "0" + k
    ascii_simple[i] = k
  while len(ascii_simple) % 3 != 0:
    ascii_simple.append("000")
  ascii_triplet = [ascii_simple[i] + ascii_simple[i+1] + ascii_simple[i+2] for i in range(0, len(ascii_simple), 3)]
  crypte = [str(pow(int(i), e, n)) for i in ascii_triplet]
  return crypte

print("ceci est un test =", codage_ascii_triplet("ceci est un test", 177952868483,199832434357))

def decodage_ascii_triplet(crypte, d, n):
  """ List x Int x Int --> Str
  Prend en parametre une liste de valeurs ASCII chiffrés et la clé privée (formée de d et n),
  et retourne la chaine de caractere de depart. """
  ascii_triplet = [str(pow(int(i), d, n)) for i in crypte]
  for i, s in enumerate(ascii_triplet):
    while len(s) < 9:
      s = "0" + s
    ascii_triplet[i] = s
  a, b, phrase, total = 0, 3, "", "".join(ascii_triplet)
  s = True
  if total == "":
    s = False
  while s:
    if total[-1] + total[-2] + total[-3] == "000":
      total = total[:-3]
    else:
      s = False
  while b < len(total)+1:
    phrase += chr(int(total[a:b]))
    a, b = b, b + 3
  return phrase

def rho_pollard(n, s=300):
  """int x s -> int
  renvoie l'un des deux nombres premiers p et q d'un entier n = p*q si la décomposition
  dure moins de s secondes
  sinon renvoie un message d'erreur"""
  t0 = time.time()
  def f(x):
    return x * x + 1
  x, y, d = 2, 2, 1
  while d == 1:
    t1 = time.time()
    if t1 >= t0 + s:
      return "Clé trop longue pour être cassée"
    x = f(x) % n
    y = f(f(y)) % n
    d = math.gcd(x - y, n)
  return d

def cassage_decomp(n, e, code):
  """int x int x list -> str x int
  casse le chiffrement RSA à partir de n puis renvoie le message en clair ainsi que la clé privée"""
  p,q = rho_pollard(n), n//rho_pollard(n)
  d = generateur_cassage(p,q,e)
  decode = decodage_ascii_triplet(code, d, n)
  return decode,d

def generateur_cassage(p,q,e):
  """int x int x int -> int
  génére la clé privée à partir de p et q et la clé publique e"""
  n = p * q
  PN = (p - 1) * (q - 1)
  d = bezout(PN, e)
  if d < 0 :
    d = d + PN
  return d