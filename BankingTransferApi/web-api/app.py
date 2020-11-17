from flask import Flask, jsonify, make_response, request
from flask_restful import Api, Resource
import bcrypt
from pymongo import MongoClient

# TODO: You are yet to COMPLETE [Loans, Testing]
app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.BankingApi
users = db.Users
bank = db.Bank

if "Bank" not in db.list_collection_names():
    bank.insert_one({
        "Bank_Name": "Lasdot Bank",
        "Bank_Funds": 10000
    })


def verify_user(username, password):
    userData = users.find_one({"Username": username})

    if userData == None:
        return False

    if not bcrypt.checkpw(password.encode("utf-8"), userData.get("Password")):
        return False

    return True

def get_debt(username):
    return users.find_one({"Username": username})["Debt"]

def get_balance(username):
    return users.find_one({"Username": username})["Balance"]
    
def update_account(username, balance):
    users.update({"Username": username}, {
        "$set": {"Balance": balance}
    })

def update_debt(username, dept):
    users.update({"Username": username}, {
        "$set": {"Debt": dept}
    })

def credit_bank():
    bank_funds = bank.find_one({"Bank_Name": "Lasdot Bank"})["Bank_Funds"]

    bank.update({"Bank_Name": "Lasdot Bank"}, {
        "$set": {"Bank_Funds": bank_funds + 1}
    })

class Registration(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")

        if verify_user(username, password): return make_response(jsonify({"Message": "This user already exists"}), 400)

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        users.insert({
            "Username": username,
            "Password": hashed,
            "Balance": 0,
            "Debt": 0
        })

        msg = jsonify({"Message": "user registration was successful"})
        return make_response(msg, 200)

class AddCash(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")
        amount = req_json.get("amount")

        is_verified = verify_user(username, password)

        if not is_verified:
            error = jsonify({"Error": "Invalid username and password"})
            return make_response(error, 400)

        balance = get_balance(username)

        amount -= 1

        # Credit bank
        credit_bank()

        # Update user balance
        users.update({"Username": username}, {
            "$set": {"Balance": balance + amount}
        })

        msg = jsonify({"Message": "Successfully credited account"})

        return make_response(msg, 200)

class Transfer(Resource):
    def post(self):
        req_json = request.get_json()

        username = req_json.get("username")
        password = req_json.get("password")
        to = req_json.get("to")
        amount = req_json.get("amount")

        is_verified = verify_user(username, password)

        if not is_verified:
            error = jsonify({"Error": "Invalid username and password"})
            return make_response(error, 400)

        # Check user balance
        balance = get_balance(username)
        balance -= 1

        if balance <= 0 or balance < amount:
            error = jsonify({"Error": "Insufficient funds"})
            return make_response(error, 400)

        # Credit Bank
        credit_bank()
        
        # Update user balance
        update_account(username, balance - amount)

        # Transfer amount
        to_balance = get_balance(to)

        update_account(to, to_balance + amount)

        msg = jsonify({"Message": "Transfer was successful"})
        return make_response(msg, 200)
        

api.add_resource(Registration, '/registration')
api.add_resource(Transfer, '/transfer')
api.add_resource(AddCash, '/add_cash')

if __name__ == "__main__":
    app.run(host="0.0.0.0")
