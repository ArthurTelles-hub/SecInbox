from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Any

# Importa as funções de utilidade local. expandir_url não é mais importado.
from .utils import (
    carregar_lista,
    verificar_palavras_chave,
    verificar_tld_suspeito,
    verificar_encurtadores, 
    verificar_dominio_recente, 
    verificar_parametros_longos,
)

def extrair_url_real(url: str) -> str:
    """
    Extrai o URL de destino real de URLs de redirecionamento ou pesquisa.
    
    Aplica 'unquote' para decodificar a URL (Correção de FN).
    """
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if parsed_url.netloc in ('www.google.com', 'google.com', 'm.google.com') and 'q' in query_params:
            return unquote(query_params['q'][0])

        return url
        
    except Exception:
        return url

def verificar_whitelist(dominio: str, whitelist: List[str]) -> bool:
    """Verifica se o domínio está na lista branca."""
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
            return {"suspicious": True, "reason": "URL inválida ou sem domínio"}

        whitelist = carregar_lista("whitelist.txt")
        if verificar_whitelist(dominio, whitelist):
            return {"suspicious": False, "reason": "Domínio na lista branca (Whitelist)"}

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
            return {"suspicious": True, "reason": "; ".join(heuristicas)}
        else:
            return {"suspicious": False, "reason": "Nenhum indicador de phishing encontrado"}

    except Exception as e:

        return {"suspicious": True, "reason": f"Erro fatal ao processar a URL: {str(e)}"}