from flask.views import MethodView
from flask_smorest import Blueprint, abort 
from schemas import CheckerSchema

from ..phishing_logic import analisar_texto

# Cria um Blueprint para as rotas de verificação de segurança
blp = Blueprint("SecurityChecker", __name__, url_prefix="/analisar", description="Endpoints para verificação de segurança")

# Endpoint para analisar texto, URLs ou e-mails
@blp.route("/", methods=["POST"])
class AnalisarResource(MethodView):
    # Nota: O decorador @blp.arguments(CheckerSchema) já injeta os dados validados no 'analise_data'
    @blp.arguments(CheckerSchema)
    def post(self, analise_data):
        input_text = analise_data.get("texto")
        input_type = analise_data.get("tipo")
        
        # Validar tipos aceitos para segurança
        if input_type.lower() not in ["url", "email"]:
            # Usar 'abort' do Flask-Smorest para tratamento de erro padronizado
            abort(400, message="Tipo de análise inválido. Use 'url' ou 'email'.")

        # 1. Chama a função do pacote modularizado
        resultado = analisar_texto(input_text, tipo=input_type)
        
        # 2. Retorna o dicionário, deixando o Flask-Smorest/Flask lidar com a conversão JSON
        return resultado