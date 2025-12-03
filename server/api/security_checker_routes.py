from flask.views import MethodView
from flask_smorest import Blueprint, abort
from schemas import SimpleBatchCheckerSchema, PhishingResponseSchema 
from phishing_logic import analisar_texto
from typing import Dict, Any

blp = Blueprint("SecurityChecker", __name__, url_prefix="/analisar", description="Endpoints para verificação de segurança")

SUSPICIOUS_KEY = "suspicious"
REASON_KEY = "reason"

def _garantir_consistencia_resultado(resultado: Dict[str, Any]) -> Dict[str, Any]:
    if SUSPICIOUS_KEY not in resultado:
        if resultado.get(REASON_KEY) and resultado.get(REASON_KEY) != "Nenhum indicador de phishing encontrado":
             resultado[SUSPICIOUS_KEY] = True
        else:
             resultado[SUSPICIOUS_KEY] = False
             
    return resultado


@blp.route("/", methods=["POST"])
class AnalisarResource(MethodView):
    @blp.arguments(SimpleBatchCheckerSchema)
    @blp.response(200, PhishingResponseSchema(many=True)) 
    def post(self, batch_data):
        
        input_type = batch_data.get("tipo_geral", "url").lower()
        input_list = batch_data.get("lista_itens", [])
        
        resultados_finais = []
        
        if input_type not in ["url", "email"]:
             abort(400, message="O campo 'tipo_geral' deve ser 'url' ou 'email'.")
        
        if not input_list:
            abort(400, message="A lista de itens ('lista_itens') não pode estar vazia.")


        for input_text in input_list:
            resultado = analisar_texto(input_text, tipo=input_type)
            resultado = _garantir_consistencia_resultado(resultado)
            resultados_finais.append(resultado)
            
        print(f"DEBUG: Lista de resultados antes da serialização: {resultados_finais}")
        
        return resultados_finais