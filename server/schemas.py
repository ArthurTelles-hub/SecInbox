from marshmallow import Schema, fields, validate

# Schema de resposta: O formato que o endpoint /analisar/ retorna para CADA ITEM
class PhishingResponseSchema(Schema):
    # NOVO CAMPO: O item analisado (URL ou e-mail) que o usuário solicitou
    analysed_item = fields.Str(
        required=True,
        metadata={"description": "O item (URL ou e-mail) que foi submetido à análise."}
    )
    suspicious = fields.Bool(
        required=True, 
        metadata={"description": "Verdadeiro se houver indícios de phishing."}
    )
    reason = fields.Str(
        required=True, 
        metadata={"description": "Detalhes dos indicadores encontrados."}
    )

# Schema de entrada: O formato esperado no body da requisição POST
class SimpleBatchCheckerSchema(Schema):
    tipo_geral = fields.Str(
        required=True, 
        validate=validate.OneOf(("url", "email")), 
        metadata={"description": "Tipo de análise aplicado a todos os itens: 'url' ou 'email'."}
    )
    lista_itens = fields.List(
        fields.Str(), 
        required=True, 
        metadata={"description": "Lista de URLs ou endereços de e-mail para análise."}
    )