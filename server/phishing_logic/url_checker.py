from urllib.parse import urlparse

from .utils import (
    carregar_lista,
    expandir_url,
    verificar_palavras_chave,
    verificar_tld_suspeito,
    verificar_dominio_recente,
    verificar_encurtadores,
    verificar_parametros_longos,
)

def verificar_whitelist(dominio: str, whitelist: list[str]) -> bool:
    dominio = dominio.lower()
    
    for item in whitelist:
        item = item.lower()

        if dominio == item:
            return True

        if dominio.endswith(f".{item}"):
            return True
            
    return False

def analisar_url(url: str) -> dict:
    heuristicas = []

    palavras_suspeitas = carregar_lista("palavras_suspeitas.txt")
    tlds_suspeitos = carregar_lista("tlds_suspeitos.txt")
    encurtadores = carregar_lista("encurtadores.txt")
    whitelist = carregar_lista("whitelist.txt")

    try: 
        parsed = urlparse(url)
        dominio = parsed.netloc.lower()
        
        if not dominio:
             return {"suspicious": True, "reason": "URL inválida ou sem domínio"}

        if verificar_whitelist(dominio, whitelist):
            return {"suspicious": False, "reason": "Domínio na lista branca (Whitelist)"}
            
        verificacoes = [
            verificar_palavras_chave(url, palavras_suspeitas),
            verificar_tld_suspeito(dominio, tlds_suspeitos),
            verificar_dominio_recente(dominio),
            verificar_encurtadores(url, dominio, encurtadores, expandir_url),
            verificar_parametros_longos(url),
        ]

        for resultado in verificacoes:
            if resultado:
                heuristicas.append(resultado)

        if heuristicas:
            return {"suspicious": True, "reason": "; ".join(heuristicas)}
        else:
            return {"suspicious": False, "reason": "Nenhum indicador de phishing encontrado"}
        
    except Exception as e:
        return {"suspicious": True, "reason": f"Erro fatal ao processar a URL: {str(e)}"}
