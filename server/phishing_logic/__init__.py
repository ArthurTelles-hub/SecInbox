from .url_checker import analisar_url
from .email_checker import analisar_email

__all__ = ["analisar_texto"]

def analisar_texto(texto: str, tipo: str) -> dict:
    texto = texto.strip()

    if not texto:
        return {"suspicius": False, "reason": "Entrada vazia"}
    
    if tipo == "url":
        return analisar_url(texto)
    elif tipo == "email":
        return analisar_email(texto)
    else:
        return  {"suspicious": True, "reason": f"Tipo de entrada não reconhecido: {tipo}"}