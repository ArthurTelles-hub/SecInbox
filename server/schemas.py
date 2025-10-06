from marshmallow import Schema, fields

class PhishingResponseSchema(Schema):
    suspicious = fields.Bool(required=True, metadata={"description": "Verdadeiro se houver indícios de phishing."})
    reason = fields.Str(required=True, metadata={"description": "Detalhes dos indicadores encontrados."})

class SimpleBatchCheckerSchema(Schema):
    tipo_geral = fields.Str(required=True, metadata={"description": "Tipo de análise aplicado a todos os itens: 'url' ou 'email'."})
    lista_itens = fields.List(
        fields.Str(), 
        required=True, 
        metadata={"description": "Lista de URLs ou endereços de e-mail para análise."}
    )