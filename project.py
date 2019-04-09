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
from generateID import generateNewID
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
			return jsonify(status="error", error="Trying to access page that requires login")
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
		mydb = myclient["Project"]
		mycol = mydb["users"]
		myquery = {"username": username}
		print("Made it in this loginuser method")
		row1 = mycol.find_one(myquery)
		print("Made it past the row1 find_one(myquery)")
		if mycol.count(myquery) == 0:
			print("no login found")
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
				return jsonify(status="error")
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('login.html'), headers)
class GetUser(Resource):
	def get(self, username):
		#get the user from the database
		my_username = username
		
		client = getMongoClient()
		db = client["Project"]
		users = db['users']
		username_query = {"username": my_username}
		my_user = users.find_one(username_query)
		if not my_user:	#no matching user
			error_msg = "No user by the name "+my_username
			return jsonify(status = "error", error = error_msg)

		return jsonify(status = "OK", user = json.loads(dumps(my_user)))	

class GetUserQuestions(Resource):
	def get(self, username):
		my_username = username

		client = getMongoClient()
		db = client["Project"]
		users = db['users']
		username_query = {"username": my_username}
		my_user = users.find_one(username_query)
		if not my_user: #no matching user
			error_msg = "No user by the name "+my_username
			return jsonify(status = "error", error = error_msg)
		return jsonify(status = "OK", questions = my_user['questions'])

class GetUserAnswers(Resource):
	def get(self, username):
		my_username = username

		client = getMongoClient()
		db = client["Project"]
		users = db['users']
		username_query = {"username": my_username}
		my_user = users.find_one(username_query)
		if not my_user: #no matching user
			error_msg = "No user by the name "+my_username
			return jsonify(status = "error", error = error_msg)
		return jsonify(status = "OK", answers = my_user['answers'])



class AddQuestion(Resource):
	@custom_validator
	def post(self):
		if request.is_json:
			json = request.get_json()
		else:
			return jsonify(status="error", error="Request isn't json")
		if not "title" in json:
			return jsonify(status="error", error="Missing parameter: title")
		if not "body" in json:
                        return jsonify(status="error", error="Missing parameter: title")
		if not "tags" in json:
			json['tags'] = []
			#return jsonify(status="error", error="Missing parameter: tags")
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
		dToInsert['user'] = {'username': get_jwt_identity(), 'reputation': 0} #TODO: search for user to find actual reputation
		dToInsert['score'] = 0
		dToInsert['view_count'] = 0
		dToInsert['answer_count'] = 0
		dToInsert['timestamp'] = time.time() #time.time() should be a unix timestamp
		dToInsert['media'] = None #might not be necessary right now bc its future milestone
		dToInsert['accepted_answer_id'] = None
		dToInsert['id'] = generateNewID() 
		dToInsert['answers'] = []	#empty array of answer IDs
		col.insert_one(dToInsert)

		#add the question to this user's question list
		user_col = db["users"]
		user_query = {"username": get_jwt_identity()}
		my_user = user_col.find_one(user_query)
		my_questions_list = my_user['questions']
		my_questions_list.append(dToInsert['id'])
		user_col.update_one(user_query, {"$set": {'questions': my_questions_list}})

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
		myquery = {"id" : int(id)}
		myquery2 = {"id" : int(id), "identifier": visit['identifier']}
		print("QUESTION ID type: ", int(id))
		if questions.count(myquery) == 0:
			return jsonify(status="error", error="No existing question ID")
		my_question = questions.find_one(myquery)
		if col.count(myquery2) == 0: #unique visit!
			visit['id'] = int(id)
			col.insert_one(visit)
			my_question['view_count'] = my_question['view_count'] + 1
			questions.update_one(myquery, { "$set": { "view_count" : my_question['view_count']} } )

		my_question = json.loads(dumps(my_question))
		return jsonify(status="OK", question=my_question)

	@custom_validator
	def delete(self, id):
		#find the question
		client = getMongoClient()
		db = client["Project"]
		questions = db['questions']
		id_query = {"id" : int(id)}
		if questions.count(id_query) == 0:
			return make_response(jsonify(status="error", error="No existing question ID"), 400)
		my_question = questions.find_one(id_query)

		#Make sure this is the right user
		this_username = get_jwt_identity()
		question_username = my_question['user']['username']

		if not this_username == question_username:
			return make_response(jsonify(status="error", error="Can't delete a question that isn't yours!"), 200)
		#delete the question
		delete_response = delete_question(my_question)
		print(delete_response)
		if delete_response['status'] == "error":
			return make_response(jsonify(status="error", error="cannot delete question"),200)

		questions.delete_one(id_query)

		return make_response(jsonify(delete_response), 200)

#delete a question
#@param a question object
#@return a json containing "status"="OK" or "error"
def delete_question(my_question):
	my_username = my_question['user']['username']
	my_ansers = my_question["answers"]

	print("DELETING FOR USER: ", my_username)
	
	# delete the reference held by "my_user"
	client = getMongoClient()
	db = client["Project"]
	users = db['users']
	user_query = {"username": my_username}
	my_user = users.find_one(user_query)
	if not my_user:	#no valid user for this question
		print("NO VALID USER HERE")
		return_data = {}
		return_data['status'] = "error"
		return return_data
	print(my_user)
	print(my_user['reputation'])
	questions_by_user = my_user['questions']

	print("Question ID to Remove: ", my_question['id'])
	print("Questions Owned by This User: ", questions_by_user)
	questions_by_user.remove(my_question['id'])
	users.update_one(user_query, {"$set": {"questions": questions_by_user}})

	#delete all answers
	for answer in my_question['answers']:
		#TODO: obviously inefficient, waiting on every delete. Use message passing?
		delete_answer(answer)
	return_data = {}
	return_data['status']="OK"
	print("RETURN DATA: ", return_data)
	return return_data
	#PART3: remove associate reputation	
#delete an answer
#@param an answer ID
#@return nothing
def delete_answer(answer_id):
	client = getMongoClient()
	db = client["Project"]
	answers = db['answers']
	answer_query = {'id' : answer_id}
	my_answer = answers.find_one(answer_query)
	
	#if answer not found
	if not my_answer:
		print("No answer found when trying to delete. Answer ID: ", my_answer['id'])
		return 

	#Delete user's reference to this answer
	my_username = my_answer['user']
	users = db['users']
	user_query = {"username": my_username}
	my_user = users.find_one(user_query)

	answers_by_user = my_user['answers']
	answers_by_user.remove(my_answer['id'])
	users.update_one(user_query, {"$set": {"answers": answers_by_user}})

	#PART3: remove associated reputation
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
		if not "body" in json:
			return jsonify(status="error", error="missing argument: 'body'")
		body = json['body']
		
		media = []
		if 'media' in json:
			media = json['media']

		client = getMongoClient()
		db = client["Project"]
		col = db["answers"]	
		dToInsert = {}
		answer_id = generateNewID()
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
		myquery = {'id' : int(id)}
		question = questions.find_one(myquery)
		question['answers'].append(answer_id)
		questions.update_one(myquery, {"$set": {"answers" : question['answers']}})
		questions.update_one(myquery, {"$set": {"answer_count" : question['answer_count'] + 1}})
		user_col = db["users"]
		user_query = {"username": get_jwt_identity()}
		my_user = users.find_one(user_query)
		my_answer_list = my_user['answers']
		my_answer_list.append(dToInsert['id'])
		user_col.update_one(user_query, {"$set": {'answers': my_answer_list}})
		
		return jsonify(status="OK", id=answer_id)  
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
		#get every answer from the question's "answers" array
		client = getMongoClient()
		db = client["Project"]
		questions = db["questions"]
		myquery = {"id" : int(id)}
		
		question = questions.find_one(myquery)
		
		if not question:
			return jsonify(status="error", error="No question with given ID")
		
		
		#get all answers from that question
		results = []
		answer_col = db["answers"]
		for answerID in question["answers"]:
			myquery2 = {"id" : answerID}
			answer = answer_col.find_one(myquery2)
			results.append(json.loads(dumps(answer)))
		
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
			my_json = request.get_json()
		else:
			return jsonify(status="error", error="Request isn't json")
		#defaults
		timestamp = time.time()
		limit = 25
		accepted = "False"	#keep parameters as a string
		q = None
		#q = ""		
		#sort_by = "score"
		#tags = []
		#has_media = "False"
		
		if 'timestamp' in my_json:
			timestamp = my_json['timestamp']
		if 'limit' in my_json:
			limit = my_json['limit']
			if limit > 100:
				limit = 100
			if limit < 1:
				limit = 1
		if 'accepted' in my_json:
                        accepted = my_json['accepted']
		if 'q' in my_json:
			q = my_json['q']
			
	
		results = [] #array of questions
		
		client = getMongoClient()
		db = client["Project"]
		col = db["questions"]
		#if accepted == "False":
		#	my_cursor = col.find({"timestamp": {"$lt": timestamp}}).sort("score")
		#else:
		#	my_cursor = col.find({"timestamp": {"$lt": timestamp}, "accepted_answer_id": {"$ne": None}}).sort("score")
		my_query = {}
		#if query string specified, only return questions with matching title or body
		if q:
			index_name = "search_index"
			index_info = col.index_information()
			if index_name not in col.index_information():
				print("GOING TO MAKE THE INDEX")
				print("INDEX_INFO: ",index_info)
				col.create_index([('body',pymongo.TEXT),('title',pymongo.TEXT)],name=index_name,default_language='english')
			print("Search Query: ", q)
			print("limit: ", limit)
			print("timestamp: ", timestamp)
			my_query["$text"] = {"$search": q}
			#my_query["_txtscore"] = {"$meta": 'textScore'}

		
		my_query["timestamp"] = {"$lt": timestamp}
		
		#if "accepted" param is on, only give questions where acc_id is not None
		if accepted != "False":
			my_query["accepted_answer_id"] = {"$ne": None}	
		if q:
			#my_cursor = col.find(my_query, {'_score', {'$meta': 'textScore'}})
			#my_cursor.sort([('_score', {'$meta': 'textScore'})])
			#my_cursor = col.find(my_query).sort([("_txtscore",{"$meta":"textScore"})])
			my_cursor = col.find(my_query, {'_txtscore':{'$meta':'textScore'}}).sort([("_txtscore",{"$meta":"textScore"})])
			##my_cursor = col.find(my_query).project({ "_txtscore": {"$meta" : "textScore"}}).sort({"_txtscore":{"$meta" : "textScore"}})
		else:
			my_cursor = col.find(my_query).sort("score")
		for i in range(limit):
			question_element = next(my_cursor, None)
			if question_element:
				results.append(json.loads(dumps(question_element)))
			else:
				break
		return jsonify(status = "OK", questions = results)

	def get(self):
		#TODO: render UI page
		return "hello search"

class Homepage(Resource):
	def get(self):
		headers = {'Content-Type':'text/html'}
		return make_response(render_template('homepage.html'), headers)

class ViewQuestion(Resource):
	def get(self,id):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('viewQuestion.html'), headers)
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
api.add_resource(Homepage, '/homepage')
api.add_resource(AddUser, '/adduser')
api.add_resource(VerifyUser, '/verify')
api.add_resource(LoginUser, '/login')
api.add_resource(LogoutUser, '/logout')
api.add_resource(LogoutUser2, '/logout2')
api.add_resource(GetUser,'/user/<username>')
api.add_resource(GetUserQuestions,'/user/<username>/questions')
api.add_resource(GetUserAnswers,'/user/<username>/answers')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(AddQuestion, '/questions/add')
api.add_resource(GetQuestion, '/questions/<id>')
api.add_resource(AddAnswer, '/questions/<id>/answers/add')
api.add_resource(GetAnswers, '/questions/<id>/answers')
api.add_resource(SearchQuestion, '/search')
api.add_resource(ViewQuestion, '/view/questions/<id>')
if __name__ == '__main__':
    app.run(host = '0.0.0.0', debug=True)
