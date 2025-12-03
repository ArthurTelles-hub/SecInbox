from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Any

from .utils import (
    carregar_lista,
    verificar_palavras_chave,
    verificar_tld_suspeito,
    verificar_encurtadores, 
    verificar_dominio_recente, 
    verificar_parametros_longos,
)

SUSPICIOUS = "suspicious"
REASON = "reason"
URL_ORIGINAL = "url_original"
URL_DESTINO = "url_destino"

def extrair_url_real(url: str) -> str:
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if parsed_url.netloc in ('www.google.com', 'google.com', 'm.google.com') and 'q' in query_params:
            return unquote(query_params['q'][0])

        return url
        
    except Exception:
        return url

def verificar_whitelist(dominio: str, whitelist: List[str]) -> bool:
    dominio = dominio.lower()
    
    for item in whitelist:
        item = item.lower()
        if dominio == item or dominio.endswith(f".{item}"):
            return True
    return False


def analisar_url(url: str) -> Dict[str, Any]:
    try:
        url_de_destino = extrair_url_real(url)

        parsed = urlparse(url_de_destino)
        dominio = parsed.netloc.lower()

        if not dominio:
            return {
                URL_ORIGINAL: url,
                SUSPICIOUS: True, 
                REASON: "URL inválida ou sem domínio"
            }

        whitelist = carregar_lista("whitelist.txt")
        if verificar_whitelist(dominio, whitelist):
            return {
                URL_ORIGINAL: url,
                URL_DESTINO: url_de_destino,
                SUSPICIOUS: False, 
                REASON: "Domínio na lista branca (Whitelist)"
            }

        palavras_suspeitas = carregar_lista("palavras_suspeitas.txt")
        tlds_suspeitos = carregar_lista("tlds_suspeitos.txt")
        encurtadores = carregar_lista("encurtadores.txt")

        heuristicas: List[str] = []
        
        caminho_e_query = unquote(parsed.path + parsed.query)

        verificacoes_rapidas = [
            verificar_palavras_chave(caminho_e_query, palavras_suspeitas),
            verificar_tld_suspeito(dominio, tlds_suspeitos),
            verificar_parametros_longos(url_de_destino),
            verificar_encurtadores(dominio, encurtadores), 
            verificar_dominio_recente(dominio), 
        ]

        for resultado in verificacoes_rapidas:
            if resultado:
                heuristicas.append(resultado)

        if heuristicas:
            return {
                URL_ORIGINAL: url,
                URL_DESTINO: url_de_destino,
                SUSPICIOUS: True, 
                REASON: "; ".join(heuristicas)
            }
        else:
            return {
                URL_ORIGINAL: url,
                URL_DESTINO: url_de_destino,
                SUSPICIOUS: False, 
                REASON: "Nenhum indicador de phishing encontrado"
            }

    except Exception as e:
        return {
            URL_ORIGINAL: url,
            SUSPICIOUS: True, 
            REASON: f"Erro fatal ao processar a URL: {type(e).__name__} - {str(e)}"
        }