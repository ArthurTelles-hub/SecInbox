from flask.views import MethodView
from flask_smorest import Blueprint, abort
from schemas import SimpleBatchCheckerSchema, PhishingResponseSchema 
from phishing_logic import analisar_texto

blp = Blueprint("SecurityChecker", __name__, url_prefix="/analisar", description="Endpoints para verificação de segurança")

@blp.route("/", methods=["POST"])
class AnalisarResource(MethodView):
    @blp.arguments(SimpleBatchCheckerSchema)
    @blp.response(200, PhishingResponseSchema(many=True)) 
    def post(self, batch_data):
        
        # 1. Extrai o tipo de análise e a lista de itens
        input_type = batch_data.get("tipo_geral", "url").lower()
        input_list = batch_data.get("lista_itens", [])
        
        resultados_finais = []
        
        # 2. Validação básica 
        if input_type not in ["url", "email"]:
             # Aborta a requisição com um erro 400 se o tipo for inválido
             abort(400, message="O campo 'tipo_geral' deve ser 'url' ou 'email'.")

        for input_text in input_list:
            resultado = analisar_texto(input_text, tipo=input_type)
            if "suspicious" not in resultado:
                if "Contém palavras suspeitas" in resultado.get("reason", ""):
                    resultado["suspicious"] = True
                else:
                    resultado["suspicious"] = False
            
            resultados_finais.append(resultado)
            
        print(f"DEBUG: Lista de resultados antes da serialização: {resultados_finais}")
        
        return resultados_finais
