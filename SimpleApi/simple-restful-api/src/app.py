from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
import math
from pymongo import MongoClient

app = Flask(__name__)
app.config["TESTING"] = True
api = Api(app)

# connect to mongo defined in docker compose 
client = MongoClient("mongodb://simple-restful-db:27017")
db = client.simpleDB
userCount = db["userCount"]

userCount.insert({
    'num_of_visits': 0
})

class Visit(Resource):
    def get(self):
        prev_count = userCount.find({})[0].get('num_of_visits')
        prev_count += 1
        userCount.update({}, {'$set': {'num_of_visits': prev_count}})
        return str("Hello user " + str(prev_count))

def error_response(json_response):
    if json_response.get('x') == None or json_response.get('y') == None:
        return 400
    return 200

class Add(Resource):
    def post(self):
        req_json = request.get_json()
        if error_response(req_json) == 400:
           error_msg = {'Error': 'Expected x and y key-value pairs'}
           return make_response(jsonify(error_msg))
        
        summation = int(req_json.get('x')) + int(req_json.get('y'))
        res = {"message": summation}
        return make_response(jsonify(res), 200)

class Subtract(Resource):
    def post(self):
        req_json = request.get_json()
        if error_response(req_json) == 400:
           error_msg = {'Error': 'Expected x and y key-value pairs'}
           return make_response(jsonify(error_msg))

        subtraction = int(req_json.get('x')) - int(req_json.get('y'))
        res = {'message': subtraction}
        return make_response(jsonify(res), 200)

class Multiply(Resource):
    def post(self):
        req_json = request.get_json()
        if error_response(req_json) == 400:
           error_msg = {'Error': 'Expected x and y key-value pairs'}
           return make_response(jsonify(error_msg))

        multiplication = int(req_json.get('x')) * int(req_json.get('y'))
        res = {'message': int(multiplication)}
        return make_response(jsonify(res), 200)

class Divide(Resource):
    def post(self):
        req_json = request.get_json()
        if error_response(req_json) == 400:
           error_msg = {'Error': 'Expected x and y key-value pairs'}
           return make_response(jsonify(error_msg))

        try:
            division = int(req_json.get('x'))/int(req_json.get('y'))
            res = {'message': int(division)}
            return make_response(jsonify(res), 200)
        except ZeroDivisionError as e:
            error_msg = {"Error": "Cannot divide by zero"}
            return make_response(jsonify(error_msg), 400)

api.add_resource(Add, '/add')
api.add_resource(Subtract, '/subtract')
api.add_resource(Multiply, '/multiply')
api.add_resource(Divide, '/divide')
api.add_resource(Visit, '/hello')

if __name__ == "__main__":
    app.run(host='0.0.0.0')

