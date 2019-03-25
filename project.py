from flask import Flask, jsonify, request, render_template, make_response
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import JWTManager
import logging
import datetime
import json
import sys
import os

from flask_jwt import JWT, jwt_required, current_identity
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (jwt_optional, verify_jwt_in_request, set_access_cookies, set_refresh_cookies, unset_jwt_cookies, create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import pymongo
from flask_jwt_extended.view_decorators import _decode_jwt_from_request
from functools import wraps

from bson.json_util import loads, dumps
import time
from addUser import AddUser, VerifyUser
#from login import LoginUser, LogoutUser, TokenRefresh
from mongoConnection import getMongoClient

from flask_jwt_extended.tokens import decode_jwt
from flask_jwt_extended.utils import has_user_loader, user_loader

app = Flask(__name__)
api = Api(app)



cors = CORS(app, resources={r"/ttt/*": {"origins": "*"}})
parser = reqparse.RequestParser()
parser.add_argument('name')
if __name__ != '__main__':
	gunicorn_logger = logging.getLogger('gunicorn.error')
	app.logger.handlers = gunicorn_logger.handlers
	app.logger.setLevel(gunicorn_logger.level)
#addheaders to chagne content type to html in here to make render template work

from flask_jwt_extended.exceptions import NoAuthorizationError
jwt = JWTManager(app)
def custom_validator(fn):
	@wraps(fn)
	def wrapper(*args, **kwargs):
		try:
			verify_jwt_in_request()
		except NoAuthorizationError:
			return jsonify(status="ERROR", error="Trying to access page that requires login")
		return fn(*args, **kwargs)   
	return wrapper


app.config['MONGO_URI'] = os.environ.get('DB')
app.config['JWT_SECRET_KEY'] = 'SECRET'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

parser2 = reqparse.RequestParser()
parser2.add_argument('username')
parser2.add_argument('password')
class LoginUser(Resource):
	def post(self):
		args = parser2.parse_args()
		username = args['username']
		password = args['password']
		myclient = getMongoClient()
		mydb = myclient["wp2"]
		mycol = mydb["users"]
		myquery = {"username": username}
		print("Made it in this loginuser method")
		row1 = mycol.find_one(myquery)
		print("Made it past the row1 find_one(myquery)")
		if mycol.count(myquery) == 0:
			return jsonify(status="error")
		else:
			if row1['password'] == password and row1['validated'] is True:
				access_token = create_access_token(identity=row1['username'])
				refresh_token = create_refresh_token(identity=row1['username'])
				mycol.update_one(myquery, {"$set": {"access_token" : access_token} })
				mycol.update_one(myquery, {"$set": {"refresh_token" : refresh_token} })
				resp = jsonify({"status":"OK"})
				set_access_cookies(resp, access_token)
				set_refresh_cookies(resp, refresh_token)
				return resp
			else:
				return jsonify(status="ERROR")
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('login.html'), headers)
class AddQuestion(Resource):
	@custom_validator
	def post(self):
		if request.is_json:
			json = request.get_json()
		else:
			return jsonify(status="error", error="Request isn't json")
		title = json['title']
		body = json['body']
		tags = json['tags']
		client = getMongoClient()
		db = client["Project"]
		col = db["questions"]
		dToInsert = {}
		dToInsert['title'] = title
		dToInsert['body'] = body
		dToInsert['tags'] = tags
		dToInsert['score'] = 0
		dToInsert['view_count'] = 0
		dToInsert['answer_count'] = 0
		dToInsert['timestamp'] = time.time() #time.time() should be a unix timestamp
		dToInsert['media'] = None #might not be necessary right now bc its future milestone
		dToInsert['accepted_answer_id'] = None
		dToInsert['id'] = col.count() + 1 #avoid zero indexing on the IDs 
		dToInsert['answers'] = []	#empty array of answer IDs
		col.insert_one(dToInsert)
		return jsonify(status="OK", id=dToInsert['id'])

class GetQuestion(Resource):
	@jwt_optional
	def get(self, id):
		visit = {}
		username = get_jwt_identity()
		if username is None: #then we should check their IP 
			visit['identifier'] = request.environ.get('HTTP_X_REAL_IP', request.remote_addr) #proxy_set_header   X-Real-IP            $remote_addr;
		else:
			visit['identifier'] = username 
		client = getMongoClient()
		db = client["Project"]
		col = db["visits"]
		questions = db['questions']
		if questions.count(myquery) == 0:
			return jsonify(status="error", error="No existing question ID")
		myquery = {"id" : id}
		myquery2 = {"id" : id, "identifier": visit['identifier']}
		question = questions.find_one(myquery)
		if col.count(myquery2) == 0: #unique visit!
			visit['id'] = id
			col.insert_one(visit)
			question['view_count'] = question['view_count'] + 1
			questions.update_one(myquery, { "$set": { "view_count" : question['view_count']} } )

		return jsonify(status="OK", question=question)



class AddAnswer(Resource):
	#add an answer to the question with the given id
	#params:
	#	body: string
	#opt	media: array of media IDs
	#return:
	#	status: "OK" or "error"
	#	id: answer id (if OK)
	#	error: message string (if error)
	@custom_validator
	def post(self, id):
		if request.is_json:
			json = request.get_json()
		else:
			return jsonify(status="error", error="Request isn't json")
		body = json['body']
		media = []
		if 'media' in json:
			media = json['media']

		client = getMongoClient()
		db = client["Project"]
		col = db["answers"]	
		dToInsert = {}
		answer_id = col.count()+1
		dToInsert['id'] = answer_id
		dToInsert['user'] = get_jwt_identity()	
		dToInsert['body'] = body
		dToInsert['score'] = 0
		dToInsert['is_accepted'] = False
		dToInsert['timestamp'] = time.time()
		dToInsert['media'] = media
		col.insert_one(dToInsert)
		
		#add this answer to the question's answer list
		questions = db["questions"]
		myquery = {'id' : id}
		question = questions.find_one(myquery)
		question['answers'].append(answer_id)
		questions.update_one(myquery, {"$set": {"answers" : question['answers']
		
		
		return jsonify(status="OK",id=str(dToInsert['id']))  
class GetAnswers(Resource):
	#get all answers for the question with the given id
	#params:
	#	none
	#return:
	#	status: "OK" or "error"
	#	answers: array of ANSWERS
	#		{id: string
	#		user: id of poster
	#		body: string
	#		score: int
	#		is_accepted: boolean
	#		timestamp: unix timestamp
	#		media: array of media IDs},...
	#	error: message stirng (if error)
	@jwt_optional
	def get(self, id):
		return jsonify(status="error", error="incomplete")
		#get every answer from the question's "answers" array
		client = getMongoClient()
		db = client["Project"]
		questions = db["questions"]
		myquery = {"id" : id}
		
		question = questions.find_one(myquery)
		
		if not question:
			return jsonify(status="error", error="No question with given ID")
		
		
		#get all answers from that question
		results = []
		answer_col = db["answers"]
		for answerID in question["answers"]:
			myquery2 = {"id" : answerID}
			answer = answer_col.find_one(myquery2)
			results.append(answer) 
		
		return jsonify(answers=results, status="OK")

class SearchQuestion(Resource):
	#search for questions
	#params:
	#opt	timestamp: only questions from this time or earlier (default=now)
	#opt	limit: max number of questions to return (default=25, max=100)
	#opt	accepted: only return questions with accepted answers (default=False)
	#return:
	#	status: "OK" or "error"
	#	questions: Array of question objects
	#	error: message string (only if status="error")
	@jwt_optional
	def post(self):
		if request.is_json:
			json = request.get_json()
		else:
			return jsonify(status="error", error="Request isn't json")
		#defaults
		timestamp = time.time()
		limit = 25
		accepted = "False"	#keep parameters as a string

		#q = ""		
		#sort_by = "score"
		#tags = []
		#has_media = "False"
		
		if 'timestamp' in json:
			timestamp = json['timestamp']
		if 'limit' in json:
                        limit = json['limit']
			if limit > 100:
				limit = 100
			if limit < 1:
				limit = 1
		if 'accepted' in json:
                        timestamp = json['accepted']
		
		results = [] #array of questions
		
		client = getMongoClient()
		db = client["Project"]
		col = db["questions"]
		#if accepted == "False":
		#	my_cursor = col.find({"timestamp": {"$lt": timestamp}}).sort("score")
		#else:
		#	my_cursor = col.find({"timestamp": {"$lt": timestamp}, "accepted_answer_id": {"$ne": None}}).sort("score")
		
		my_query = {"timestamp": {"$lt": timestamp}}
		
		#if "accepted" param is on, only give questions where acc_id is not None
		if accepted != "False":
			my_query["accepted_answer_id"] = {"$ne": None}	
		
		my_cursor = col.find(my_query).sort("score")
 		for i in range(limit):
			question_element = my_cursor.hasNext() ? myCursor.next() : None
			if not question_element:
				break
			else:
				results.append(question_element)
		return jsonify(status = "OK", questions = results)

	def get(self):
		#TODO: render UI page
		return "hello search"

blacklist = set()
@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
	#query the blacklist collection for {"access_token" : decrypted_token}}
	jti = decrypted_token['jti']
	return jti in blacklist
	#query collection if count is not 0: return true else return false
class LogoutUser(Resource):
	@custom_validator
	def post(self):
		resp = jsonify({'status': "OK"})
		unset_jwt_cookies(resp)
		return resp
		#jti = get_raw_jwt()['jti']
		#blacklist.add(jti)
		#return jsonify(status="OK")

class LogoutUser2(Resource):
	@jwt_refresh_token_required
	def post(self):
		jti = get_raw_jwt()['jti']
		blacklist.add(jti)
		return jsonify(status="OK")
class TokenRefresh(Resource):
	@jwt_refresh_token_required
	def post(self):
		current_user = get_jwt_identity()
		access_token = create_access_token(identity=current_user)
		resp = jsonify({"status":"OK"})
		set_access_cookies(resp, access_token)
		return resp

api.add_resource(AddUser, '/adduser')
api.add_resource(VerifyUser, '/verify')
api.add_resource(LoginUser, '/login')
api.add_resource(LogoutUser, '/logout')
api.add_resource(LogoutUser2, '/logout2')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(AddQuestion, '/questions/add')
api.add_resource(GetQuestion, '/questions/<id>')
api.add_resource(AddAnswer, '/questions/<id>/answers/add')
api.add_resource(GetAnswers, '/questions/<id>/answers')
api.add_resource(SearchQuestion, '/search')

if __name__ == '__main__':
    app.run(host = '0.0.0.0', debug=True)
