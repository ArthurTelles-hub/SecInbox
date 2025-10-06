from flask.views import MethodView
from flask_smorest import Blueprint, abort 
from marshmallow import fields
from schemas import SimpleBatchCheckerSchema, PhishingResponseSchema
from phishing_logic import analisar_texto

blp = Blueprint("SecurityChecker", __name__, url_prefix="/analisar", description="Endpoints para verificação de segurança")

# Endpoint para analisar texto, URLs ou e-mails
@blp.route("/", methods=["POST"])
class AnalisarResource(MethodView):
    @blp.arguments(SimpleBatchCheckerSchema)
    @blp.response(200, fields.List(fields.Nested(PhishingResponseSchema)))
    def post(self, batch_data):
        input_type = batch_data.get("tipo_geral", "url").lower()
        input_list = batch_data.get("lista_itens", [])

        resultados_finais = []

        if input_type in input_list:
            abort(400,message="O campo tipo_geral deve ser 'url' ou 'email'.")
        
        for input_text in input_list:
            resultado = analisar_texto(input_text, tipo=input_type)
            resultados_finais.append(resultado)
        
        return resultados_finais