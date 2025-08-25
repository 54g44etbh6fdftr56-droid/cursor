from random import choices
from string import ascii_letters, digits
from db.connection import words

def rand_search(k=3):
    return ' '.join(choices(words, k=k))

def valid_username(username: str) -> bool:
    return username.isalnum()

def valid_quote(quote: str) -> bool:
    return len(quote) > 0 and len(quote) <= 2000 and not any(char in quote for char in '%<>/\\&`[]{}()|$')