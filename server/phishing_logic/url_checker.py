import whois
from urllib.parse import urlparse
from datetime import datetime
import time
import utils

def verificar_dominio_recente(dominio: str) -> str | None:
    time.sleep(1.0)
    
    try:
        info = whois.whois(dominio)
        if info and info.creation_date:
            criacao = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date

            if isinstance(criacao, str):
                # Formato comum WHOIS
                try:
                    criacao = datetime.strptime(criacao.split('.')[0], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    return "A data de criação WHOIS não pode ser processada"
                
            if isinstance(criacao, datetime):
                dias = (datetime.now() - criacao).days
                if dias < 90:
                    return f"Domínio registrado recentemente ({dias} dias atrás)"
                
    except whois.parser.PywhoisError:
        return "Falha na consulta (Pode indicar domínio inexistente ou consulta bloqueada)"
    except Exception as e:
        return f"Erro ao tentar verificar WHOIS: {str(e)}"
    
    return None

def verificar_encurtadores(url: str, dominio: str, encurtadores: list[str]) -> str | None:
    if dominio in encurtadores:
        motivo = ["URL encurtada"]
        # Tenta expandir para verificar destino final
        expandida = utils.expandir_url(url)
        if expandida and expandida != url:
            motivo.append(f"URL expandida (destino final): {expandida}")
        return "; ".join(motivo)
    
def verificar_parametros_longos(url: str) -> str | None:
    if url.count("?") > 1 or url.count("=") > 3:
        return "URL com muitos parâmetros (chance de ofuscamento ou reastreamentos complexo)"
    return None

def analisar_url(url: str) -> dict:
    palavras_suspeitas = utils.carregar_lista("palavras_suspeitas.txt")
    tlds_suspeitos = utils.carregar_lista("tlds_suspeitos.txt")
    encurtadores = utils.carregar_lista("encurtadores.txt")

    heuristicas = []

    try: 
        parsed = urlparse(url)
        dominio = parsed.netloc.lower()

        verficacoes = [
            utils.verificar_palavras_chave(url, palavras_suspeitas),
            utils.verificar_tld_suspeito(url, tlds_suspeitos),
            verificar_dominio_recente(dominio),
            verificar_encurtadores(url, dominio, encurtadores),
            verificar_parametros_longos(url),
        ]

        # Coleta todas as razões não nulas
        for resultado in verficacoes:
            if resultado:
                heuristicas.append(resultado)

        if heuristicas:
            return {"suspicius": True, "reason": "; ".join(heuristicas)}
        else:
            return {"suspicius": False, "reason": "Nenhum indicador de phishing encontrado"}
        
    except Exception as e:
        return {"suspicius": True, "reason": f"Erro fatal ao processar a URL: {str(e)}"}