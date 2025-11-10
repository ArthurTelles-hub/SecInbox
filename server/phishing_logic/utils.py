import os
import requests
from urllib.parse import urlparse
import datetime
import whois

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

def verificar_dominio_recente(dominio: str, dias_limite: int = 30) -> str | None:
    try:
        info = whois.whois(dominio)
        data_criacao = info.creation_date

        if isinstance(data_criacao, list):
            data_criacao = data_criacao[0]

        if not data_criacao:
            return None

        dias_passados = (datetime.datetime.now() - data_criacao).days
        if dias_passados <= dias_limite:
            return f"Domínio criado há apenas {dias_passados} dias"
        return None
    except Exception:
        return None
    
def verificar_encurtadores(url: str, dominio: str, encurtadores: list[str], expandir_url_func) -> str | None:
    dominio = dominio.lower()

    # Verifica se o domínio faz parte da lista de encurtadores conhecidos
    if any(encurtador in dominio for encurtador in encurtadores):
        # Tenta expandir a URL
        expandida = expandir_url_func(url)

        if expandida:
            return f"URL encurtada detectada ({dominio}), expandida para {expandida}"
        else:
            return f"URL encurtada detectada ({dominio}), não foi possível expandir"
    return None

from urllib.parse import urlparse, parse_qs

def verificar_parametros_longos(url: str, limite_tamanho: int = 100, limite_parametros: int = 5) -> str | None:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return None

        # Verifica quantidade total de parâmetros
        if len(params) > limite_parametros:
            return f"Quantidade suspeita de parâmetros ({len(params)})"

        # Verifica se algum valor de parâmetro é muito longo
        for key, values in params.items():
            for value in values:
                if len(value) > limite_tamanho:
                    return f"Parâmetro '{key}' possui valor excessivamente longo ({len(value)} caracteres)"

        return None
    except Exception:
        return None
