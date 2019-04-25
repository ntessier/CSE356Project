from flask import Flask, jsonify, request, render_template, make_response, current_app
from flask_restful import Resource, Api, reqparse
import pymongo
import json
import random
import string
import smtplib, ssl
import time
from mongoConnection import getMongoClient
from mongoAccess import *
#import logging
from queueMail import queueMail 
parser1 = reqparse.RequestParser()
parser1.add_argument('email')
parser1.add_argument('key')
parser1.add_argument('username')
parser1.add_argument('password')

class AddUser(Resource):
	def post(self):
		
		#server = smtplib.SMTP('localhost', 587)
	#	server = smtplib.SMTP('localhost')
		#server.ehlo()
		#server.starttls(context = ssl.create_default_context())
		#server.ehlo()
		#server.login("warmupproject2@gmail.com", "dummyemail")
		#start_time = time.time()

		args = parser1.parse_args()
		username = args['username']
		password = args['password']
		email = args['email']

		print("Adding a user ", username)
		print("With email ", email) 

		#print("username: " + username + " password: " + password + " email: " + email)

		myclient = getMongoClient()
		mydb = myclient["Project"]
		mycol = mydb["users"]
		#print("mycol: " + str(mycol))
		myquery = {"email": email}
		myquery2 = {"username": username}
		row1 = mycol.find_one(myquery)
		row2 = mycol.find_one(myquery2)
		
				
		if not row1 and not row2:
			#start_time = time.time()
			dataToInsert = {}
			dataToInsert['username'] = username
			dataToInsert['password'] = password
			dataToInsert['email'] = email 
			dataToInsert['validated'] = False
			dataToInsert['verificationCode'] = getKey()
			dataToInsert['reputation'] = 1
			dataToInsert['questions'] = []	#list of question IDs
			dataToInsert['answers'] = [] 	#list of answer IDs
			dataToInsert['upvoted'] = []
			dataToInsert['downvoted'] = []
			dataToInsert['waived_downvoted'] = []
			#end_time = time.time()
			#REFACTOR new entry in 'user'
#			mycol.insert_one(dataToInsert)
			upsertUserNOW(dataToInsert)
#			upsertUserNOW(dataToInsert)
			msg2 = "\nHello " + username + "!\n validation key: <" + dataToInsert['verificationCode'] + ">"
			#msg = "\nHello " + username + "!\n Please click this link to\
			print('right above queueMail in addUser')			
#verify your account for Stack.\n http://130.245.171.188/verify?email=" + email + "&key=" + dataToInsert['verificationCode']
			queueMail(email, msg2)
			#print("QUEUED MAIL SUCCESSFULY\n")
			#end_time = time.time()
			#print(end_time - start_time)
			print("NEW USER ADDED", username)
			return jsonify(status="OK")
		else:
			return make_response(jsonify(status="error", error="Account already exists!"), 401)
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('adduser.html'), headers)
class VerifyUser(Resource):
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('verify.html'), headers)
	def post(self):
		#print("VALIDATION ATTEMPT")
		if request.is_json:
			json = request.get_json()
		else:
			print("Not json")
			return make_response(jsonify(status = "error", error = "not json"), 400)	
		email = json['email']
		key = json['key']
		#myclient = getMongoClient()
		#mydb = myclient["Project"]
		#mycol = mydb["users"]
		#myquery = {"email" : email}
		#row = mycol.find_one(myquery)
		row = getUserByEmail(email)
		tries = 0
		max_tries = 10
		while not row and tries < max_tries:
			#print("email not found, trying again " + email)
			tries += 1
			#time.sleep(.5)
			row = getUserByEmail(email)
		if not row:
			print("Failed after many tries, " + email)
			return make_response(jsonify(status="error", error="Email not found!"), 401)
		else:
			print("FOUND USER WHILE VERIFYING: ", row['username'])
			if row['validated'] is False and row['verificationCode'] == key:
				print("\n VALIDATED WITH CODE ", row['username'])
				#REFACTOR update 'validated' in 'user'
				#mycol.update_one(myquery, { "$set": { "validated" : True} })
				row['validated'] = True
				upsertUserNOW(row)
				return jsonify(status="OK")
			elif row['validated'] is False and key == 'abracadabra':
				print("\n VALIDATED SUCCESSFULLY WITH BACKDOOR ",row['username'] )
				#REFACTOR update 'validated' in 'user'
				#mycol.update_one(myquery, { "$set": { "validated" : True} })
				row['validated'] = True
				upsertUserNOW(row)

				return jsonify(status="OK")
			else:
				#print("\nVALIDATION ERROR")
				return make_response(jsonify(status="error", error="VerificationCode doesn't match or user is already validated!"), 402)

			





def getKey():
	randomk = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(16)])
	return randomk
