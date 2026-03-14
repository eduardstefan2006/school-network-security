"""
Funcții utilitare pentru validare și alte operații comune.
"""
import re

# Lungimea minimă acceptată pentru parole
MIN_PASSWORD_LENGTH = 8


def validate_password(password):
    """
    Validează complexitatea parolei.

    Cerințe:
      - Minim 8 caractere
      - Cel puțin o literă mare
      - Cel puțin o literă mică
      - Cel puțin o cifră

    Returnează (True, '') dacă parola este validă sau
    (False, mesaj_eroare) dacă nu îndeplinește cerințele.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f'Parola trebuie să aibă cel puțin {MIN_PASSWORD_LENGTH} caractere.'
    if not re.search(r'[A-Z]', password):
        return False, 'Parola trebuie să conțină cel puțin o literă mare.'
    if not re.search(r'[a-z]', password):
        return False, 'Parola trebuie să conțină cel puțin o literă mică.'
    if not re.search(r'\d', password):
        return False, 'Parola trebuie să conțină cel puțin o cifră.'
    return True, ''
