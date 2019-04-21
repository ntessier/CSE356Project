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
from mongoAccess import *
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
			return make_response(jsonify(status="error", error="Trying to access page that requires login"), 400)
		return fn(*args, **kwargs)   
	return wrapper
from mediaAccess import GetMedia, AddMedia

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
			return make_response(jsonify(status="error"), 400)
		else:
			if row1['password'] == password and row1['validated'] is True:
				access_token = create_access_token(identity=row1['username'])
				refresh_token = create_refresh_token(identity=row1['username'])
				#REFACTOR update 'access_token' in 'user'
				#REFACTOR update 'refresh_token' in 'user'
				mycol.update_one(myquery, {"$set": {"access_token" : access_token} })
				mycol.update_one(myquery, {"$set": {"refresh_token" : refresh_token} })
				resp = jsonify({"status":"OK"})
				set_access_cookies(resp, access_token)
				set_refresh_cookies(resp, refresh_token)
				return resp
			else:
				return make_response(jsonify(status="error"), 400)
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('login.html'), headers)
class GetUser(Resource):
	def get(self, username):
		#get the user from the database
		my_username = username
		
#		client = getMongoClient()
#		db = client["Project"]
#		users = db['users']
#		username_query = {"username": my_username}
#		my_user = users.find_one(username_query)
		my_user = getUserByName(my_username)
		if not my_user:
			error_msg = "No user by the name "+my_username
			return make_response(jsonify(status = "error", error = error_msg), 400)

		return jsonify(status = "OK", user = json.loads(dumps(my_user)))	

class GetUserQuestions(Resource):
	def get(self, username):
		my_username = username

#		client = getMongoClient()
#		db = client["Project"]
#		users = db['users']
#		username_query = {"username": my_username}
#		my_user = users.find_one(username_query)
		my_user = getUserByName(my_username)
		if not my_user:
			error_msg = "No user by the name "+my_username
			return make_response(jsonify(status = "error", error = error_msg), 400)
		return jsonify(status = "OK", questions = my_user['questions'])

class GetUserAnswers(Resource):
	def get(self, username):
		my_username = username

#		client = getMongoClient()
#		db = client["Project"]
#		users = db['users']
#		username_query = {"username": my_username}
#		my_user = users.find_one(username_query)
		my_user = getUserByName(my_username)
		if not my_user: 
			error_msg = "No user by the name "+my_username
			return make_response(jsonify(status = "error", error = error_msg), 400)
		return jsonify(status = "OK", answers = my_user['answers'])



class AddQuestion(Resource):
	@custom_validator
	def post(self):
		if request.is_json:
			json = request.get_json()
			#print("JSON upon entering AddQuestion: " + dumps(json))
		else:
			print("request not json")
			return make_response(jsonify(status="error", error="Request isn't json"), 400)
		if not "title" in json:
			print("Missing a title")
			return make_response(jsonify(status="error", error="Missing parameter: title"), 400)
		if not "body" in json:	
			print("Missing a body")
			return make_response(jsonify(status="error", error="Missing parameter: title"), 400)
		if not "tags" in json:
			print("Missing tags")
			#json['tags'] = []
			return make_response(jsonify(status="error", error="Missing parameter: tags"), 400)
		title = json['title']
		body = json['body']
		tags = json['tags']
#		client = getMongoClient()
#		db = client["Project"]
#		col = db["questions"]
		dToInsert = {}
		dToInsert['title'] = title
		dToInsert['body'] = body
		dToInsert['tags'] = tags
		dToInsert['user'] = {'username': get_jwt_identity(), 'reputation': 1}
		dToInsert['score'] = 1
		dToInsert['view_count'] = 0
		dToInsert['answer_count'] = 0
		dToInsert['timestamp'] = time.time() #time.time() should be a unix timestamp
		dToInsert['media'] = [] #might not be necessary right now bc its future milestone
		dToInsert['accepted_answer_id'] = None
		dToInsert['id'] = generateNewID() 
		dToInsert['answers'] = []	#empty array of answer IDs
		#print(dumps(dToInsert))
		#REFACTOR add entry in 'question'
		#col.insert_one(dToInsert)
		upsertQuestion(dToInsert)

		#add the question to this user's question list
		#user_col = db["users"]
		#user_query = {"username": get_jwt_identity()}
		#my_user = user_col.find_one(user_query)
		my_user = getUserByName(get_jwt_identity())
		my_questions_list = my_user['questions']
		my_questions_list.append(dToInsert['id'])
		#REFACTOR update 'questions' in 'user'
		#user_col.update_one(user_query, {"$set": {'questions': my_questions_list}})
		upsertUser(my_user)
		
		#print("right before the return, ID: ", dToInsert['id'])	
		#print("right before the return,ID (int): ", int(dToInsert['id']))
	
		return jsonify(status="OK", id=dToInsert['id'])

class GetQuestion(Resource):
	@jwt_optional
	def get(self, id):
		print("STARTING GET QUESTION")
		visit = {}
		username = get_jwt_identity()
		if username is None: #then we should check their IP 
			visit['identifier'] = request.environ.get('HTTP_X_REAL_IP', request.remote_addr) #proxy_set_header   X-Real-IP            $remote_addr;
		else:
			visit['identifier'] = username 
		client = getMongoClient()
		db = client["Project"]
		questions = db["questions"]
		col = db["visits"]
		myquery2 = {"id" : id, "identifier": visit['identifier']}
		print("QUESTION ID type: ", id)
		
		my_question = getQuestionByID(id)
		if not my_question:
			return make_response(jsonify(status="error", error="No existing question ID"), 400)
		
		if col.count(myquery2) == 0: #unique visit!
			visit['id'] = id
			#REFACTOR new entry in 'visit'
			col.insert_one(visit)
			my_question['view_count'] = my_question['view_count'] + 1
			#REFACTOR update 'view_count' in questions
			#questions.update_one(myquery, { "$set": { "view_count" : my_question['view_count']} } )
			upsertQuestion(my_question)

		my_question = json.loads(dumps(my_question))
		print("Question Contents: ", my_question)
		#my_question['id'] = my_question['id']
		return jsonify(status="OK", question=my_question)

	@custom_validator
	def delete(self, id):
		#find the question
		client = getMongoClient()
		db = client["Project"]
		questions = db['questions']
		id_query = {"id": id}

		my_question = getQuestionByID(id)
		if not my_question:
			return make_response(jsonify(status="error", error="No existing question ID"), 400)
		#Make sure this is the right user
		this_username = get_jwt_identity()
		question_username = my_question['user']['username']

		if not this_username == question_username:
			return make_response(jsonify(status="error", error="Can't delete a question that isn't yours!"), 400)
		#delete the question
		delete_response = delete_question(my_question)
		print(delete_response)
		if delete_response['status'] == "error":
			return make_response(jsonify(status="error", error="cannot delete question"),400)
		#REFACTOR delete entry from 'questions'
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
#	my_user = users.find_one(user_query)
	my_user = getUserByName(my_username)
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
	my_user['questions'] = questions_by_user
	#REFACTOR update 'questions' in 'user'
#	users.update_one(user_query, {"$set": {"questions": questions_by_user}})
	upsertUser(my_user)

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
#	client = getMongoClient()
#	db = client["Project"]
#	answers = db['answers']
#	answer_query = {'id' : answer_id}
	#my_answer = answers.find_one(answer_query)
	my_answer = getAnswerByID(answer_id)
	#if answer not found
	if not my_answer:
		print("No answer found when trying to delete. Answer ID: ", my_answer['id'])
		return 

	#Delete user's reference to this answer
	my_username = my_answer['user']
#	users = db['users']
#	user_query = {"username": my_username}
	#my_user = users.find_one(user_query)
	my_user = getUserByName(my_username)

	answers_by_user = my_user['answers']
	answers_by_user.remove(my_answer['id'])
	my_user['answers'] = answers_by_user
	#REFACTOR update 'answers' in 'user'
#	users.update_one(user_query, {"$set": {"answers": answers_by_user}})
	upsertUser(my_user)
class UpvoteQuestion(Resource):
	@custom_validator
	def upvote_question(self, id):
		if request.is_json():
			my_json = request.get_json()
		else:
			return make_response(jsonify(status="error", error="Request isn't json"), 400)
		vote = None	#true if upvote, false if downvote
		if 'upvote' in my_json:
			vote = my_json['upvote']
		if not vote:
			return make_response(jsonify(status="error", error="Invalid arguments: upvote not found"), 400)

		my_question = getQuestionByID(id)
		my_question_id = my_question['id']
		if not my_question:
			return make_response(jsonify(status="error", error="No question with given ID"), 400)
		my_user = getUserByName(my_answer['user'])
		if not my_user:
			return make_response(jsonify(status="error", error="No corresponding poster???"), 400)

		voting_user = getUserByName(get_jwt_identity())

		#TODO: call vote functions
		if vote:
			upvote_object(voting_user, my_question, my_user)
		else:
			downvote_object(voting_user, my_question, my_user)
		return jsonify(status = "OK")


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
			return make_response(jsonify(status="error", error="missing argument: 'body'"), 400)
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
		dToInsert['score'] = 1
		dToInsert['is_accepted'] = False
		dToInsert['timestamp'] = time.time()
		dToInsert['media'] = media
		print(dumps(dToInsert))
		#REFACTOR new entry in 'answers'
		#col.insert_one(dToInsert)
		upsertAnswer(dToInsert)
		
		#add this answer to the question's answer list
		#questions = db["questions"]
		#myquery = {'id' : id}
		#question = questions.find_one(myquery)
		question = getQuestionByID(id)
		
		if not question:
			return make_response(jsonify(status="error", error="no question with given ID"), 400)

		question['answers'].append(answer_id)
		question['answer_count'] = question['answer_count']+1
		#REFACTOR update 'answers' in 'questions'
		#REFACTOR update 'answer_count' in 'questions'
		#questions.update_one(myquery, {"$set": {"answers" : question['answers']}})
		#questions.update_one(myquery, {"$set": {"answer_count" : question['answer_count'] + 1}})
		upsertQuestion(question)

		#user_col = db["users"]
		#user_query = {"username": get_jwt_identity()}
		#my_user = user_col.find_one(user_query)
		my_user = getUserByName(get_jwt_identity())
		#my_answer_list = my_user['answers']
		#my_answer_list.append(dToInsert['id'])
		my_user['answers'].append(dToInsert['id'])
		#REFACTOR update 'answers' in 'user'
		#user_col.update_one(user_query, {"$set": {'answers': my_answer_list}})
		upsertUser(my_user)
		
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
		question = getQuestionByID(id)
		if not question:
			return make_response(jsonify(status="error", error="No question with given ID"), 400)
				
		#get all answers from that question
		results = []
		for answerID in question["answers"]:
			answer = getAnswerByID(answerID)
			results.append(json.loads(dumps(answer)))
		
		return jsonify(answers=results, status="OK")

class UpvoteAnswer(Resource):
	@custom_validator
	def upvote_answer(self, id):
		if request.is_json():
			my_json = request.get_json()
		else:
			return jsonify(status="error", error="Request isn't json")
		vote = None	#true if upvote, false if downvote
		if 'upvote' in my_json:
			vote = my_json['upvote']
		if not vote:
			return make_response(jsonify(status="error", error="Invalid arguments: upvote not found"), 400)

		my_answer = getAnswerByID(id)
		my_answer_id = my_answer['id']
		if not my_answer:
			return make_response(jsonify(status="error", error="No answer with given ID"), 400)
		my_user = getUserByName(my_answer['user'])
		if not my_user:
			return make_response(jsonify(status="error", error="No corresponding poster???"), 400)

		voting_user = getUserByName(get_jwt_identity())

		#TODO: call vote functions
		if vote:
			upvote_object(voting_user, my_answer, my_user)
		else:
			downvote_object(voting_user, my_answer, my_user)
		return jsonify(status = "OK")


#upvote an object
#params are all jsons
#responsible for updating everything about the jsons, and reporting to appropriate "write" calls
def upvote_object(voter, obj, obj_owner):
	my_id = obj['id']

	#remove downvote
	if my_id in voter['waived_downvoted']:
		obj['score'] += 1
		voter['waived_downvoted'].remove(my_id)
	elif obj['id'] in voter['downvoted']:
		obj['score'] += 1
		voter['downvoted'].remove(my_id)
		obj_owner['reputation'] += 1

	#unupvote
	if obj['id'] in voter['upvoted']:
		obj['score'] -= 1
		voter['upvoted'].remove(obj['id'])
		if obj_owner['reputation'] > 2:
			obj_owner['reputation'] -= 1
		#TODO: consider waiving removal for low rep user?
		
	
	#upvote	
	else:
		#increment owner rep. increment object score. add to "upvoted" list
		obj['score'] += 1
		obj_owner['reputation'] += 1
		voter['upvoted'].append(obj['id'])
	
	upsertUser(voter) 
	upsertUser(obj_owner)
	if 'is_accpted' in obj:
		upsertAnswer(obj)
	else:
		upsertQuestion(obj)



#downvote an object
def downvote_object(voter, obj, obj_owner):
	owner_changed = False
	my_id = obj['id']
	
	#remove upvote
	if my_id in voter['upvoted']:
		obj['score'] -= 1
		voter['upvoted'].remove(my_id)
		if obj_owner['reputation'] >= 2:
			obj_owner['reputation'] -= 1
			owner_changed = True
			
	
	#undownvote
	if obj['id'] in voter['waived_downvoted']:
		#remove waived downvote
		#increment object score. do nothing to owner rep. remove from list
		obj['score'] += 1
		voter['waived_downvoted'].remove(obj['id'])
	elif obj['id'] in voter['downvoted']:
		#remove valid downvote
		#increment object score. increment owner score. remove from list
		obj['score'] += 1
		voter['downvoted'].remove(obj['id'])
		obj_owner['reputation'] += 1
		owner_changed = True

	#downvote	
	else:
		obj['score'] -= 1
		if obj_owner['reputation'] < 2:
			#do nothing to rep. add to "waived" list
			voter['waived_downvoted'].append(obj['id'])
			
		else:
			#decrement rep. add to "downvoted" list
			obj_owner['reputation'] -= 1
			voter['downvoted'].append(obj['id'])
			owner_changed = True


	upsertUser(voter) 
	if owner_changed:
		upsertUser(obj_owner)
	if 'is_accpted' in obj:
		upsertAnswer(obj)
	else:
		upsertQuestion(obj)
	
class AcceptAnswer(Resource):
	@custom_validator
	def accept_answer(self, id):
		current_user = getUserByName(get_jwt_identity())
		for questionID in current_user['questions']:
			question = getQuestionByID(questionID)
			for answerID in question['answers']:
				if answerID == id:
					question['accepted_answer_id'] = id
					upsertQuestion(question)
					answer = getAnswerByID(id)
					userWithAnswer = getUserByName(answer['user'])
					userWithAnswer['reputation'] = userWithAnswer['reputation'] + 15
					upsertUser(userWithAnswer)
					return jsonify(status="OK")

		return make_response(jsonify(status="error", message = "answer ID may not be users answer or answer ID doesn't exst"), 400)
		




#edited?
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
		sort_by = "score"
		tags = []
		has_media = "False"
		

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
		if 'sort_by' in my_json:
			sort_by = my_json['sort_by']
		if 'tags' in my_json:
			tags = my_json['tags']
		if 'has_media' in my_json:
			has_media in my_json['has_media']

			
	
		results = [] #array of questions
		
		client = getMongoClient()
		db = client["Project"]
		col = db["questions"]
		my_query = {}
		
		#if query string specified, only return questions with matching title or body
		if q:
			index_name = "search_index"
			index_info = col.index_information()
			if index_name not in col.index_information():
				col.create_index([('body',pymongo.TEXT),('title',pymongo.TEXT)],name=index_name,default_language='none')
			#print("Search Query: ", q)
			#print("limit: ", limit)
			#print("timestamp: ", timestamp)
			my_query["$text"] = {"$search": q}
		
		my_query["timestamp"] = {"$lt": timestamp}
		
		#if "accepted" param is on, only give questions where acc_id is not None
		if accepted != "False":
			my_query["accepted_answer_id"] = {"$ne": None}
		if has_media != "False":
			my_query["media"] = {"$ne": []}
		if tags != []:
			my_query["tags"] = {"$all": tags}
		if q:
			#my_cursor = col.find(my_query, {'_score', {'$meta': 'textScore'}})
			#my_cursor.sort([('_score', {'$meta': 'textScore'})])
			#my_cursor = col.find(my_query).sort([("_txtscore",{"$meta":"textScore"})])
			#TODO: use elasticsearch
			#my_cursor = col.find(my_query, {'_txtscore':{'$meta':'textScore'}}).sort([("_txtscore",{"$meta":"textScore"})])
			if sort_by != "score":
				my_cursor = col.find(my_query, {'_txtscore':{'$meta':'textScore'}}).sort([("_txtscore",{"$meta":"textScore"})]).limit(limit).sort("timestamp", pymongo.DESCENDING)
			else:
				my_cursor = col.find(my_query, {'_txtscore':{'$meta':'textScore'}}).sort([("_txtscore",{"$meta":"textScore"})]).limit(limit).sort("score", pymongo.DESCENDING)


		else:
			if sort_by != "score":
				my_cursor = col.find(my_query).sort("timestamp", pymongo.DESCENDING)
			else:
				my_cursor = col.find(my_query).sort("score", pymongo.DESCENDING)

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
api.add_resource(UpvoteQuestion, '/questions/<id>/upvote')
api.add_resource(UpvoteAnswer, '/answers/<id>/upvote')
api.add_resource(AcceptAnswer, '/answers/<id>/accept')
api.add_resource(SearchQuestion, '/search')
api.add_resource(AddMedia, '/addmedia')
api.add_resource(GetMedia, '/media/<id>')
api.add_resource(ViewQuestion, '/view/questions/<id>')
if __name__ == '__main__':
    app.run(host = '0.0.0.0', debug=True)
