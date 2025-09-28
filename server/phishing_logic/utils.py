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