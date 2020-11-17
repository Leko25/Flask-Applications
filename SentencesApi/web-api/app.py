"""
High Level Design
-----------------
Registration of a user 0 tokens
Each user gets 10 tokens
Store a sentence on our database for 1 token
Retrieve his stored sentence on our database for 1 token
"""

import bcrypt
from flask import Flask, jsonify, make_response, request
from flask_restful import Api, Resource
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.sentencesDB
users = db["Users"]

def verify_user(username, password):
    userData = users.find_one({"Username": username})

    if userData == None:
        return False

    if not bcrypt.checkpw(password.encode("utf-8"), userData.get("Password")):
        return False

    return True

def get_tokens(username):
    userData = users.find_one({"Username": username})

    return userData.get("Tokens")
    
class Registration(Resource):
    def post(self):
        req_json = request.get_json()

        # Get username and password from posted data 
        username = req_json.get("username")
        password = req_json.get("password")

        # Hash user password
        password = password.encode("utf-8")
        hashed_pwd = bcrypt.hashpw(password, bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pwd,
            "Sentences": [],
            "Tokens": 10
        })

        res_msg = {"Message": "user has been successfully registered"}
        return make_response(res_msg, 200)

class Store(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")
        sentence = req_json.get("sentence")

        # verify username and password
        is_verified = verify_user(username, password)

        if not is_verified:
            error = {"Error": "incorrect username and password"}
            return make_response(jsonify(error), 400)
        
        # Verify user has sufficient tokens
        tokens = get_tokens(username)

        if tokens == 0:
            error = {"Error": "insufficient tokens"}
            return make_response(jsonify(error), 400)

        userData = users.find_one({"Username": username})
        sentences = userData.get("Sentences")

        sentences.append(sentence)
        tokens -= 1

        users.update_one({
            "Username": username
        }, {
            "$set": {"Sentences": sentences, "Tokens": tokens}
        })

        msg = {"Message": "saved sentence!"}
        return make_response(jsonify(msg), 200)

class GetSentence(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")

        # verify user credentials
        is_verified = verify_user(username, password)

        if not is_verified:
            error = {"Error": "incorrect username and password"}
            return make_response(jsonify(error), 400)

        userData = users.find_one({"Username": username})
        sentences = ",".join(userData.get("Sentences"))

        if len(sentences) == 0:
            msg = {"Message": "you have no sentences saved"}
            return make_response(jsonify(msg), 200)

        return make_response(sentences, 200)

class Unregister(Resource):
    def delete(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")

        is_verified = verify_user(username, password)

        if not is_verified:
            error = {"Error": "incorrect username and password"}
            return make_response(jsonify(error), 400)

        users.delete_one({"Username": username})
        msg = {"Message": "Successfully deleted account"}

        return make_response(jsonify(msg), 200)


api.add_resource(Registration, '/registration')
api.add_resource(Store, '/store')
api.add_resource(GetSentence, '/sentences')
api.add_resource(Unregister, '/unregister')





if __name__ == "__main__":
    app.run(host="0.0.0.0")
