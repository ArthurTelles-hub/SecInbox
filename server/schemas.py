from marshmallow import Schema, fields

class PhishingResponseSchema(Schema):
    suspicious = fields.Bool(required=True, metadata={"description": "Verdadeiro se houver indícios de phishing."})
    reason = fields.Str(required=True, metadata={"description": "Detalhes dos indicadores encontrados."})

# Flask-Smorest reconhece '__root__' e documenta como um array puro.
class ResponseListWrapperSchema(Schema):
    __root__ = fields.List(fields.Nested(PhishingResponseSchema))

class SimpleBatchCheckerSchema(Schema):
    tipo_geral = fields.Str(required=True, metadata={"description": "Tipo de análise aplicado a todos os itens: 'url' ou 'email'."})
    lista_itens = fields.List(
        fields.Str(), 
        required=True, 
        metadata={"description": "Lista de URLs ou endereços de e-mail para análise."}
    )
