from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import timedelta
from flasgger import Swagger, swag_from
import logging

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = 'segredoJWT'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)

jwt = JWTManager(app)
swagger = Swagger(app)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

users = []

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Autenticação'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        201: {'description': 'Usuário registrado com sucesso'},
        400: {'description': 'Email e senha são obrigatórios'}
    }
})
def register():
    data = request.json
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Email e senha são obrigatórios'}), 400
    users.append(data)
    logging.info(f"Usuário registrado: {data['email']}")
    return jsonify({'message': 'Usuário registrado com sucesso!'}), 201

@app.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Autenticação'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        200: {'description': 'Login realizado com sucesso e token retornado'},
        401: {'description': 'Credenciais inválidas'},
        400: {'description': 'Dados de entrada inválidos'}
    }
})
def login():
    data = request.json
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Email e senha são obrigatórios'}), 400
    user = next((u for u in users if u['email'] == data['email'] and u['password'] == data['password']), None)
    if not user:
        logging.warning(f"Falha ao fazer login: {data['email']}")
        return jsonify({'message': 'Credenciais inválidas'}), 401
    token = create_access_token(identity=data['email'])
    logging.info(f"Token gerado para {data['email']}: {token}")
    return jsonify({'token': token}), 200

@app.route('/musicas', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Músicas'],
    'security': [{'Bearer': []}],
    'responses': {
        200: {'description': 'Lista de músicas retornada com sucesso'},
        401: {'description': 'Token JWT inválido ou ausente'}
    }
})
def listar_musicas():
    current_user = get_jwt_identity()
    logging.info(f"Usuário autenticado: {current_user}")
    musicas = [
        {"id": 1, "titulo": "Strobe", "artista": "deadmau5", "genero": "Progressive House"},
        {"id": 2, "titulo": "Levels", "artista": "Avicii", "genero": "Progressive House"},
        {"id": 3, "titulo": "Satisfaction", "artista": "Benny Benassi", "genero": "Electro House"},
        {"id": 4, "titulo": "One Kiss (with Dua Lipa)", "artista": "Calvin Harris", "genero": "Dance-Pop"},
        {"id": 5, "titulo": "Where Are Ü Now (with Justin Bieber)", "artista": "Skrillex & Diplo", "genero": "Future Bass"}
    ]
    return jsonify(musicas), 200

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'message': 'Requisição inválida: ' + str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'message': 'Não autorizado: ' + str(error)}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Recurso não encontrado: ' + str(error)}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'message': 'Erro interno do servidor: ' + str(error)}), 500

if __name__ == '__main__':
    app.run(debug=True)