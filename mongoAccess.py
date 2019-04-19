#Methods for reads and writes to the database
from mongoConnection import getMongoClient


#Get Question by ID
#return the Question document, None if no question exists
	#NOT responsible for updating the view count
def getQuestionByID(my_id):
	client = getMongoClient()
	db = client["Project"]
	question_col = db["questions"]
	my_query = {"id" : my_id}
	my_question = question_col.find_one(my_query)
	return my_question

#Write Question
def upsertQuestion(my_question):
	client = getMongoClient()
	db = client["Project"]
	question_col = db["questions"]
	question_col.replace_one({"id" : my_question['id']}, my_question, upsert=True)

#Get Answer by ID
#return the Answer document, None if no answer exists
def getAnswerByID(my_id):
	client = getMongoClient()
	db = client["Project"]
	answer_col = db['answers']
	my_query = {"id" : my_id}
	my_answer = answer_col.find_one(my_query)
	return my_answer

#Write answer
def upsertAnswer(my_answer):
	client = getMongoClient()
	db = client["Project"]
	answer_col = db['answers']
	answer_col.replace_one({"id" : my_answer['id']}, my_answer, upsert=True)

	
#Get User by email
#return the User document, None if no user exists
def getUserByEmail(my_email):
	client = getMongoClient()
	db = client["Project"]
	user_col = db["users"]
	my_query = {"email" : my_email}
	my_user = user_col.find_one(my_query)

	return my_user

#Get User by username
#return the User document, None if no user exists
def getUserByName(my_name):
	client = getMongoClient()
	db = client["Project"]
	user_col = db["users"]
	my_query = {"username" : my_name}
	my_user = user_col.find_one(my_query)

	return my_user

#Write user
def upsertUser(my_user):
	client = getMongoClient()
	db = client["Project"]
	user_col = db["users"]
	user_col.replace_one({'username': my_user["username"]}, my_user, upsert=True)
