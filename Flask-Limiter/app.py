from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta'

jwt = JWTManager(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

usuarios = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if username in usuarios and usuarios[username] == password:
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    else:
        return jsonify({"msg": "Usuario o contraseña incorrectos"}), 401

@app.route('/register', methods=['POST'])
@limiter.limit("9 per minute")
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if username in usuarios:
        return jsonify({"msg": "El usuario ya fue creado"}), 400

    usuarios[username] = password
    return jsonify({"msg": "Usuario registrado exitosamente"}), 201

@app.route('/protected', methods=['GET'])
@jwt_required()
@limiter.limit("20 per hour")
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Límite de peticiones excedido. Por favor, intenta de nuevo más tarde."), 429

if __name__ == '__main__':
    app.run(debug=True)
