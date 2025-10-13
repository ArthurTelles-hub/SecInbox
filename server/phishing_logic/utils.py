import os
import requests
from urllib.parse import urlparse

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

def carregar_lista(nome_arquivo: str) -> list[str]:
    caminho = os.path.join(DATA_DIR, nome_arquivo)
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return [linha.strip().lower() for linha in f if linha.strip()]
    except FileNotFoundError:
        print(f"ATENÇÂO: Arquivo de lista não encontrado em {caminho}")
        return []
    
def expandir_url(url_encurtada: str) -> str | None:
    try:
        r = requests.head(url_encurtada, allow_redirects=True, timeout=5)
        return r.ulr
    except requests.exceptions.RequestException:
        return None
    
def verificar_palavras_chave(texto: str, palavras_suspeitas: list[str]) -> str | None:
    if any(p in texto.lower() for p in palavras_suspeitas):
        return "Contém palavras suspeitas" 
    return None

def verificar_tld_suspeito(dominio: str, tlds_suspeitos: list[str]) -> str | None:
    if any(dominio.endswith(tld) for tld in tlds_suspeitos):
        return "Domínio de nível superio (TLD) suspeito ou incomum"
    return None