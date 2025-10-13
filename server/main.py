import os
from flask import Flask, jsonify
from flask_smorest import Api
from dotenv import load_dotenv

# Imports para o rate limiting
# Utiliza o IP do usuário como base
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Importa os Blueprints dos arquivos de rotas
from api.security_checker_routes import blp as SecurityCheckerBlueprint
from api.status_routes import blp as StatusBlueprint

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# CSRF protection não habilitada pois esta API é RESTful e stateless,
# a autenticação é feita via tokens nos headers.
app = Flask(__name__)

# Configurações do Flask-Smorest para a documentação
app.config["API_TITLE"] = "API SecureInbox"
app.config["API_VERSION"] = "v1"
app.config["OPENAPI_VERSION"] = "3.0.2"
app.config["OPENAPI_URL_PREFIX"] = "/"
app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"

# Armazenamento definido na memory para uso simples ste o momento
app.config["RATELIMIT_STORAGE_URI"] = "memory://"

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    # A regra vale para todos os endpoints sem um limite próprio definido
    default_limits=["100 per minute"]
) 

api = Api(app)

# Registra os Blueprints na API
api.register_blueprint(SecurityCheckerBlueprint)
api.register_blueprint(StatusBlueprint)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "message": "Limite de requisições atingido, tente mais tarde.",
        "limit_info": str(e.description)
    }), 429

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)