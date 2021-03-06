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
#from mediaAccess import getCassandraSession
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
			print("INVALID LOGIN")
			#print(request.headers)
			#for cookie in request.cookies:
			#	print("COOKIE FOUND: ", cookie)
			return make_response(jsonify(status="error", error="Trying to access page that requires login"), 400)
		return fn(*args, **kwargs)   
	return wrapper
from mediaAccess import GetMedia, AddMedia, removeMediaByID, getCassandraSession

app.config['MONGO_URI'] = os.environ.get('DB')
app.config['JWT_SECRET_KEY'] = 'SECRET'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_ACCESS_COOKIE_NAME'] = "access_token"
app.config['JWT_REFRESH_COOKIE_NAME'] = "refresh_token"
parser2 = reqparse.RequestParser()
parser2.add_argument('username')
parser2.add_argument('password')
class LoginUser(Resource):
	def post(self):
		args = parser2.parse_args()
		username = args['username']
		password = args['password']
		#myclient = getMongoClient()
		#mydb = myclient["Project"]
		#mycol = mydb["users"]
		#myquery = {"username": username}
		row1 = getUserByName(username)
		print("Attmepted Login: ", username)
		if not row1:
			print("no user found")
			return make_response(jsonify(status="error", error="no user found"), 400)
		else:
			if row1['password'] == password and row1['validated'] is True:
				access_token = create_access_token(identity=row1['username'])
				refresh_token = create_refresh_token(identity=row1['username'])
				#REFACTOR update 'access_token' in 'user'
				#REFACTOR update 'refresh_token' in 'user'
				row1['access_token'] = access_token
				row1['refresh_token'] = refresh_token
				upsertUser(row1)
				#mycol.update_one(myquery, {"$set": {"access_token" : test_token} })
				#mycol.update_one(myquery, {"$set": {"refresh_token" : refresh_token} })
				print("Logged in successfully: ", row1['username'])
				resp = jsonify({"status":"OK"})
			
				set_access_cookies(resp, access_token)
#				set_refresh_cookies(resp, refresh_token)
				return resp
			else:
				return make_response(jsonify(status="error",error="user not verified or incorrect password"), 401)
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
		#print(request.headers)
		#for cookie in request.cookies:
		#	print("COOKIE FOUND: ", cookie)
		#print(request.headers)
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

		#print("Identity: ", get_jwt_identity())
		media = []
		if "media" in json:
			media = json['media'] 
		title = json['title']
		body = json['body']
		tags = json['tags']
#		client = getMongoClient()
#		db = client["Project"]
#		col = db["questions"]
		user = getUserByName(get_jwt_identity())
		dToInsert = {}
		dToInsert['title'] = title
		dToInsert['body'] = body
		dToInsert['tags'] = tags
		dToInsert['user'] = {'username': user['username'], 'reputation': user['reputation']}
		dToInsert['score'] = 0
		dToInsert['view_count'] = 0
		dToInsert['answer_count'] = 0
		dToInsert['timestamp'] = time.time() #time.time() should be a unix timestamp
		dToInsert['media'] = []
		dToInsert['accepted_answer_id'] = None
		dToInsert['id'] = generateNewID() 
		dToInsert['answers'] = []	#empty array of answer IDs
		
		#update the 'used' field of media
		for media_id in media:
			#create a document that maps a mediaID to an ObjectID
			#associateMedia(media_id, dToInsert['id'])	
			result = associateMedia(media_id, dToInsert['id'], get_jwt_identity())
			if result == "error":
				return make_response(jsonify(status="error", error="media does not exist or is already associated with another object"), 400)
		dToInsert['media'] = media
			
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
		#print("STARTING GET QUESTION")
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
		#print("QUESTION ID type: ", id)
		
		my_question = getQuestionByID(id)
		if not my_question:
			return make_response(jsonify(status="error", error="No existing question ID"), 400)
		user = my_question['user']['username']
		user = getUserByName(user)
		my_question['user']['reputation'] = user['reputation'] #MIGHT NEED TO UPSERT THIS IF DOESN"T WORK BUT TRYING TO AVOID UPSERT OPERATION
		if col.count(myquery2) == 0: #unique visit!
			visit['id'] = id
			#REFACTOR new entry in 'visit'
			col.insert_one(visit)
			my_question['view_count'] = my_question['view_count'] + 1
			#REFACTOR update 'view_count' in questions
			#questions.update_one(myquery, { "$set": { "view_count" : my_question['view_count']} } )
			#upsertQuestion(my_question)
		upsertQuestion(my_question)
		my_question = json.loads(dumps(my_question))
		#print("Question Contents: ", my_question)
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
		#print(delete_response)
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

	#print("DELETING FOR USER: ", my_username)
	
	# delete the reference held by "my_user"
#	client = getMongoClient()
#	db = client["Project"]
#	users = db['users']
#	user_query = {"username": my_username}
#	my_user = users.find_one(user_query)
	my_user = getUserByName(my_username)
	if not my_user:	#no valid user for this question
		print("NO VALID USER in delete_question")
		return_data = {}
		return_data['status'] = "error"
		return return_data
	#print(my_user)
	#print(my_user['reputation'])
	questions_by_user = my_user['questions']

	#print("Question ID to Remove: ", my_question['id'])
	#print("Questions Owned by This User: ", questions_by_user)
	questions_by_user.remove(my_question['id'])
	my_user['questions'] = questions_by_user
	
	#remove reputation gained by the poster
	my_user['reputation'] -= my_question['score']
	if my_user['reputation'] < 1:
		my_user['reputation'] = 1

	#remove associated media from the database
	for media_id in my_question['media']:
		#remove from cassandra based on ID
		result = removeMediaByID(media_id)
		if result == "error":
			print("tried to delete invalid media")
			return make_response(jsonify(status="error", error="invalid media"), 400)

#	users.update_one(user_query, {"$set": {"questions": questions_by_user}})
	upsertUser(my_user)

	#delete all answers (Do we need to?)
	for answer in my_question['answers']:
#		# obviously inefficient, waiting on every delete. Use message passing?
		delete_answer(answer)
	return_data = {}
	return_data['status']="OK"
	#print("RETURN DATA: ", return_data)
	return return_data
	#PART3: remove associate reputation	
#delete an answer
#@param an answer ID
#@return nothing
def delete_answer(answer_id):
	client = getMongoClient()
	db = client["Project"]
	answers = db['answers']
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
	my_user['reputation'] -= my_answer['score']
	if my_user['reputation'] < 2:
		my_user['reputation'] = 1

	#TODO: delete associated media
	for media_id in my_answer['media']:
		removeMediaByID(media_id)
	#REFACTOR update 'answers' in 'user'
#	users.update_one(user_query, {"$set": {"answers": answers_by_user}})
	upsertUser(my_user)
	answers.delete_one({'id': answer_id})
	

class UpvoteQuestion(Resource):
	@custom_validator
	def post(self, id):
		if request.is_json:
			my_json = request.get_json()
		else:
			return make_response(jsonify(status="error", error="Request isn't json"), 400)
		vote = None	#true if upvote, false if downvote
		if 'upvote' in my_json:
			vote = my_json['upvote']
		else:
			vote = True
		#if not vote:
		#	return make_response(jsonify(status="error", error="Invalid arguments: upvote not found"), 400)

		my_question = getQuestionByID(id)
		#print("vote = " + str(vote))
		#print("question by ID of " + id + " is " + str(my_question))
		my_question_id = my_question['id']
		if not my_question:
			return make_response(jsonify(status="error", error="No question with given ID"), 400)
		my_user = getUserByName(my_question['user']['username'])
		if not my_user:
			return make_response(jsonify(status="error", error="No corresponding poster???"), 400)

		voting_user = getUserByName(get_jwt_identity())
		#print("voting_user is " + voting_user['username'])
		#TODO: call vote functions
		if vote == True:
			#print("about to upvote")
			upvote_object(voting_user, my_question, my_user)
		else:
			#print("about to downvote")
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
		
		question = getQuestionByID(id)
		if not question:
			return make_response(jsonify(status="error", error="no question with given ID"), 400)


				
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
		dToInsert['score'] = 0
		dToInsert['is_accepted'] = False
		dToInsert['timestamp'] = time.time()
		dToInsert['media'] = media
		dToInsert['question'] = id
		#update the 'used' field of media
		for media_id in media:
                        #create a document that maps a mediaID to an ObjectID
			result = associateMedia(media_id, dToInsert['id'], get_jwt_identity())
			if result == "error":
				return make_response(jsonify(status="error", error="media already associated with another object"), 400)
				

		#print(dumps(dToInsert))
		#REFACTOR new entry in 'answers'
		#col.insert_one(dToInsert)
		upsertAnswer(dToInsert)
		
		#add this answer to the question's answer list
		#questions = db["questions"]
		#myquery = {'id' : id}
		#question = questions.find_one(myquery)
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
	def post(self, id):
		if request.is_json:
			my_json = request.get_json()
		else:
			return jsonify(status="error", error="Request isn't json")
		vote = None	#true if upvote, false if downvote
		if 'upvote' in my_json:
			vote = my_json['upvote']
		else:
			vote = True
		#if not vote:
		#	return make_response(jsonify(status="error", error="Invalid arguments: upvote not found"), 400)

		my_answer = getAnswerByID(id)
		if not my_answer:
			return make_response(jsonify(status="error", error="No answer with given ID"), 400)
		my_answer_id = my_answer['id']
		#if not my_answer:
		#	return make_response(jsonify(status="error", error="No answer with given ID"), 400)
		my_user = getUserByName(my_answer['user'])
		if not my_user:
			return make_response(jsonify(status="error", error="No corresponding poster???"), 400)

		voting_user = getUserByName(get_jwt_identity())

		#TODO: call vote functions
		if vote == True:
			upvote_object(voting_user, my_answer, my_user)
		else:
			downvote_object(voting_user, my_answer, my_user)
		return jsonify(status = "OK")


#upvote an object
#params are all jsons
#responsible for updating everything about the jsons, and reporting to appropriate "write" calls
def upvote_object(voter, obj, obj_owner):
	my_id = obj['id']
	#print(voter)
	
	client = getMongoClient()
	db = client['Project']
	col = db['users']

	#remove downvote
	if my_id in voter['waived_downvoted']:
		#print("Removing waived downvote")
		obj['score'] += 1
		voter['waived_downvoted'].remove(my_id)
		#col.update_one({"username":voter['username']}, {"$pull":{"waived_downvoted":my_id}})
	elif obj['id'] in voter['downvoted']:
		#print("Removing normal downvote")
		obj['score'] += 1
		voter['downvoted'].remove(my_id)
		#col.update_one({"username":voter['username']}, {"$pull":{"downvoted":my_id}})
		obj_owner['reputation'] += 1
		#obj['user']['reputation'] = obj_owner['reputation']
	#unupvote
	if obj['id'] in voter['upvoted']:
		obj['score'] -= 1
		#print("removing upvote")
		voter['upvoted'].remove(obj['id'])
		#col.update_one({"username":voter['username']}, {"$pull":{"upvoted":my_id}})
		if obj_owner['reputation'] >= 2:
			obj_owner['reputation'] -= 1
		#	obj['user']['reputation'] = obj_owner['reputation'] 
		#TODO: consider waiving removal for low rep user?
	#upvote	
	else:
		#print('name of voter is ' + voter['username'])
		#print("NORMAL UPVOTE")
		#increment owner rep. increment object score. add to "upvoted" list
		obj['score'] += 1
		obj_owner['reputation'] += 1
		#obj['user']['reputation'] = obj_owner['reputation']
		voter['upvoted'].append(obj['id'])
		#print('Voters upvoted array after appending id ' + str(voter['upvoted']))
		#col.update_one({"username":voter['username']}, {"$push":{"upvoted":my_id}})	
	
	#print(voter)
	if voter['username'] == obj_owner['username']:
		voter['reputation'] = obj_owner['reputation']
		upsertUser(voter)
	else:
		upsertUser(voter)
		upsertUser(obj_owner)
	#print("USERNAME OF VOTER: ", voter["username"])
	#col.update_one({"username":voter['username']}, {"$set":{"upvoted":voter['upvoted']}})
	#col.update_one({"username":voter['username']}, {"$set":{"downvoted":voter['downvoted']}})
	#col.update_one({"username":voter['username']}, {"$set":{"waived_downvoted":voter['waived_downvoted']}})
	if 'is_accepted' in obj:
		upsertAnswer(obj)
	else:
		obj['user']['reputation'] = obj_owner['reputation']
		upsertQuestion(obj)



#downvote an object
def downvote_object(voter, obj, obj_owner):
	owner_changed = False
	my_id = obj['id']
	#remove upvote
	if my_id in voter['upvoted']:
		#print("decrementing for upvote removal")
		obj['score'] -= 1
		voter['upvoted'].remove(my_id)
		if obj_owner['reputation'] >= 2:
			obj_owner['reputation'] -= 1
			#obj['user']['reputation'] -= 1
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
		#obj['user']['reputation'] += 1
		owner_changed = True

	#downvote	
	else:
		#print("DECREMENTING SCORE FOR DV")
		obj['score'] -= 1
		if obj_owner['reputation'] < 2:
			#do nothing to rep. add to "waived" list
			voter['waived_downvoted'].append(obj['id'])
			
		else:
			#decrement rep. add to "downvoted" list
			obj_owner['reputation'] -= 1
			#obj['user']['reputation'] = obj_owner['reputation']
			voter['downvoted'].append(obj['id'])
			owner_changed = True


#	upsertUser(voter) 
	if owner_changed and voter['username'] == obj_owner['username']:
		voter['reputation'] = obj_owner['reputation']
		upsertUser(voter)
	else:
		upsertUser(obj_owner)
		upsertUser(voter)
	if 'is_accepted' in obj:
		upsertAnswer(obj)
	else:
		obj['user']['reputation'] = obj_owner['reputation']
		upsertQuestion(obj)
	
class AcceptAnswer(Resource):
	@custom_validator
	def post(self, id):
		
		answer = getAnswerByID(id)
		if not answer:
			return make_response(jsonify(status="error", error="No answer with that ID"), 401)
		question = getQuestionByID(answer['question'])
		current_user = getUserByName(get_jwt_identity())

		#check for correct user
		if not question['id'] in current_user['questions']:
			return make_response(jsonify(status="error", error="Only the original poster can accept an answer"), 400)

		#check for question already closed
		if question['accepted_answer_id'] is not None:
			return make_response(jsonify(status="error", error="Question has been closed"), 402)

		#for questionID in current_user['questions']:
		#	for answerID in question['answers']:
		#		if answerID == id:
		
		#close the question
		question['accepted_answer_id'] = id
		upsertQuestion(question)
		
		#update the answer
		answer['is_accepted'] = True
		upsertAnswer(answer)

		#increase answerer reputation
		userWithAnswer = getUserByName(answer['user'])
		userWithAnswer['reputation'] = userWithAnswer['reputation'] + 15
		upsertUser(userWithAnswer)
		return jsonify(status="OK")

		#return make_response(jsonify(status="error", message = "answer ID may not be users answer or answer ID doesn't exst"), 400)
		




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
			has_media = my_json['has_media']

			
	
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
		headers = {'Content-Type':'text/html'}
		return make_response(render_template('search.html'), headers)

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
	#TODO: just for testing
	@custom_validator
	def get(self):
		resp = jsonify({'status': "OK"})
		unset_jwt_cookies(resp)
		return resp

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
class Reset(Resource):
	def get(self):
		client = getMongoClient()
		#TODO: change this to accomodate for sharding
		mydb = client['Project']
		#mydb.command("dropDatabase")
		for col_name in mydb.list_collection_names():
			mydb[col_name].delete_many({})
		session = getCassandraSession()
		session.execute("TRUNCATE images")
class Default(Resource):
	def get(self):
		headers = {'content-Type':'text/html'}
		return make_response(render_template('homepage.html'), headers)


def associateMedia(media_id, object_id, username):
	client = getMongoClient()
	db = client["Project"]
	media_col = db["media"]

	my_media = media_col.find_one({"media_id": media_id})

	#does not exist
	if not my_media:
		return "error"
	if not my_media['object_id'] is None:
		print("DUPLICATE EXISTS")
		return "error"
	if not username == my_media['username']:
		print("NOT THE RIGHT USER")
		return "error"
	else:
		media_col.update_one({"media_id":media_id}, {"$set": {"object_id":object_id}})
		return "OK"

api.add_resource(Default, '/')
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
api.add_resource(Reset, '/reset')
api.add_resource(ViewQuestion, '/view/questions/<id>')
if __name__ == '__main__':
    app.run(host = '0.0.0.0', debug=True)
