import os
from urllib.parse import urlparse, parse_qs
from typing import List, Optional
from datetime import datetime
import re

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

def carregar_lista(nome_arquivo: str) -> List[str]:
    caminho = os.path.join(DATA_DIR, nome_arquivo)
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return [linha.strip().lower() for linha in f if linha.strip() and not linha.strip().startswith('#')]
    except FileNotFoundError:
        return []
    except Exception:
        print(f"ATENÇÂO: Arquivo de lista não encontrado em {caminho}")
        return []
    
def verificar_palavras_chave(texto: str, palavras_suspeitas: List[str]) -> Optional[str]:
    if any(p in texto.lower() for p in palavras_suspeitas):
        return "Contém palavras suspeitas" 
    return None

def verificar_tld_suspeito(dominio: str, tlds_suspeitos: List[str]) -> Optional[str]:
    dominio_partes = dominio.split('.')
    if len(dominio_partes) > 1:
        tld_candidato = dominio_partes[-1]
        if tld_candidato in tlds_suspeitos:
             return f"Domínio de nível superior (TLD) suspeito ou incomum: .{tld_candidato}"
    return None

def verificar_dominio_recente(dominio: str, dias_limite: int = 30) -> Optional[str]:
    # whois foi removido. Esta função agora é um stub que retorna sempre None.
    return None
    
def verificar_encurtadores(dominio: str, encurtadores: List[str]) -> Optional[str]:
    dominio = dominio.lower()

    if any(encurtador == dominio for encurtador in encurtadores):
        return f"URL encurtada detectada ({dominio})"
    return None


def verificar_parametros_longos(url: str, limite_tamanho: int = 70, limite_parametros: int = 5) -> Optional[str]:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return None

        if len(params) > limite_parametros:
            return f"Quantidade suspeita de parâmetros ({len(params)})"

        for key, values in params.items():
            for value in values:
                if len(value) > limite_tamanho:
                    return f"Parâmetro '{key}' possui valor excessivamente longo ({len(value)} caracteres)"

        return None
    except Exception:
        return None