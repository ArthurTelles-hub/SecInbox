from marshmallow import Schema, fields

# --- Schemas de Saída ---

class PhishingResponseSchema(Schema):
    """Schema para a resposta de um único resultado de análise de phishing."""
    suspicious = fields.Bool(required=True, metadata={"description": "Verdadeiro se houver indícios de phishing."})
    reason = fields.Str(required=True, metadata={"description": "Detalhes dos indicadores encontrados."})

# NOVO SCHEMA: Wrapper para a lista de respostas.
# Flask-Smorest reconhece '__root__' e documenta como um array puro (não um objeto com chave 'results').
class ResponseListWrapperSchema(Schema):
    """Wrapper para forçar o Marshmallow/Swagger a tratar a resposta como uma lista pura."""
    __root__ = fields.List(fields.Nested(PhishingResponseSchema))

# --- Schema de Entrada de Lote (Conforme correção anterior) ---

class SimpleBatchCheckerSchema(Schema):
    """Schema para a requisição de análise em lote com tipo único."""
    tipo_geral = fields.Str(required=True, metadata={"description": "Tipo de análise aplicado a todos os itens: 'url' ou 'email'."})
    lista_itens = fields.List(
        fields.Str(), 
        required=True, 
        metadata={"description": "Lista de URLs ou endereços de e-mail para análise."}
    )
