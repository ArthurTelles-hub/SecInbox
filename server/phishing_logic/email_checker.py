from .utils import (
    verificar_palavras_chave, 
    verificar_tld_suspeito, 
    carregar_lista
)

def _validar_formato(email:str) -> tuple[str | None, str | None] | dict:
    try:
        partes_email = email.split("@")
        if len(partes_email) != 2:
            raise ValueError("Formato de e-mail inválido (faltando @)")
        
        usuario = partes_email[0].lower()
        dominio = partes_email[1].lower()
        
        if not usuario or not dominio:
            raise ValueError("Nome de usuário ou domínio vazio")
        
        return usuario, dominio
    
    except ValueError as e:
        return {"suspicius": True, "reason": f"Formato de e-mail inválido: {e}"}
    except IndexError:
        return {"suspicius": True, "reason": "Formato de e-mail inválido ou incopleto"}
    except Exception as e:
        return {"suspicius": True, "reason": f"Erro interno na validação do formato: {str(e)}"}
    
def analisar_email(email: str) -> dict:
    resultado_formato = _validar_formato(email)

    if isinstance(resultado_formato, dict):
        return resultado_formato
    
    usuario, dominio = resultado_formato

    palavras_suspeitas = carregar_lista("palavras_suspeitas.txt")
    tlds_suspeitos = carregar_lista("tlds_suspeitos.txt")

    heuristicas = []

    try:
        verificacoes = [
            verificar_tld_suspeito(dominio, tlds_suspeitos),
            verificar_palavras_chave(usuario, palavras_suspeitas),
        ]

        for resultado in verificacoes:
            if resultado:
                heuristicas.append(resultado)

        if heuristicas:
            return {"suspicious": True, "reason": "; ".join(heuristicas)}
        else:
            return {"suspicious": False, "reason": "Nenhum indicador de phishing encontrado no e-mail"}
        
    except Exception as e:
        # Erro geral de processamento
        return {"suspicious": True, "reason": f"Erro fatal ao processar o e-mail: {str(e)}"}