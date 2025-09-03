"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import bcrypt
from flask import Flask, request, jsonify, url_for, Blueprint
from flask_jwt_extended import create_access_token
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route('/register', methods=["POST"])
def register_user():

    
    body = request.get_json()
    new_pass = bcrypt.hashpw(body['password'].encode(),bcrypt.gensalt())

    new_user = User()
    new_user.username = body["username"]
    new_user.email = body["email"]
    new_user.password = new_pass.decode()
    new_user.is_active = True
   
    

    db.session.add(new_user)
    db.session.commit()

    return jsonify("Usuario registrado correctamente")

@api.route("/login", methods=["POST"])
def user_login():
    body = request.get_json()
    print(body)
    user = User.query.filter_by(email=body["email"]).first()

    if user is None:
        return jsonify("La cuenta no existe"), 404

    if bcrypt.checkpw(body["password"].encode(), user.password.encode()):
        user_serialize = user.serialize()
        token = create_access_token(identity=str(user_serialize["id"]))

        return jsonify({"token": token, "user": user_serialize}), 200

    return jsonify("contraseña no valida"), 400
