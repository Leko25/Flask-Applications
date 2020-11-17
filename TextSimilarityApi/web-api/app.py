import bcrypt
import spacy
from flask import Flask, jsonify, make_response, request
from flask_restful import Api, Resource
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)

# connect to database resource in yml file
client = MongoClient("mongodb://db:27017")
db = client.TextSimilarityDB
users = db["Users"]
if "Admin" not in db.list_collection_names():
    admin = db.create_collection(
    name="Admin",
    max=1,
    size=500,
    capped=True
)

admin = db["Admin"]

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

class RegisterAdmin(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("admin_username")
        password = req_json.get("admin_password")

        if admin.find_one({"AdminName": username}) != None: return make_response(jsonify({"Error": "Single admin registration"}), 400)

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        admin.insert_one({
            "AdminName": username,
            "AdminPassword": hashed
        })

        msg = jsonify({"Message": "Admin successfully created"})
        return make_response(msg, 200)

class Register(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")

        if verify_user(username, password): return make_response(jsonify({"Message": "This user already exists"}), 400)

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        users.insert({
            "Username": username,
            "Password": hashed,
            "Tokens": 10
        })

        msg = jsonify({"Message": "user has been registered successfully"})
        return make_response(msg, 200)

class SimilarityDetector(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")

        if not verify_user(username, password):
            error = jsonify({"Error": "not a valid username and password"})
            return make_response(error, 400)

        tokens = get_tokens(username)

        if tokens == 0:
            error = jsonify({"Error": "not enough tokens. please refill!"})
            return make_response(error, 400)

        doc_1 = req_json.get("document1")
        doc_2 = req_json.get("document2")

        # Determine edit distance
        nlp = spacy.load("en_core_web_sm")
        doc_1 = nlp(doc_1)
        doc_2 = nlp(doc_2)

        # Calculate the similarity between both documents
        ratio = doc_1.similarity(doc_2)

        # Decrease user tokens by 1
        tokens -= 1
        users.update_one({"Username": username}, {"$set": {"Tokens": tokens}})

        msg = jsonify(
            {
                "Message": "Similarity calucalted!",
                "Similarity": ratio
            }
        )

        return make_response(msg, 200)

class Refill(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        admin_pw = req_json.get("admin_pw")
        refill_amount = req_json.get("refill")

        # Verify user
        if users.find_one({"Username": username}) == None: return make_response(jsonify({"Error": "user does not exist"}), 400)

        # Get admin password
        adminPassword = admin.find({})[0]["AdminPassword"]

        # Check admin password
        if not bcrypt.checkpw(admin_pw.encode("utf-8"), adminPassword):
            error = jsonify({"Error": "Unsuccessful admin login attempt"})
            return make_response(error, 400)

        # Get userData
        userData = users.find_one({"Username": username})
        tokens = get_tokens(username)
        tokens += refill_amount

        # Update user data
        users.update_one({"Username": username}, {
            "$set": {"Tokens": tokens}
        })

        msg = jsonify({"Message": "Successfully refilled user tokens"})
        return make_response(msg, 200)

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

api.add_resource(Register, '/registration')
api.add_resource(SimilarityDetector, '/similarity')
api.add_resource(RegisterAdmin, '/admin_registration')
api.add_resource(Refill, '/refill')
api.add_resource(Unregister, '/unregister')


if __name__ == "__main__":
    app.run(host="0.0.0.0")
