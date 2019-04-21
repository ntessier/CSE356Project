from flask import Flask, jsonify, request, render_template, make_response, current_app
from flask_restful import Resource, Api, reqparse
import pymongo
import json
import random
import string
import smtplib, ssl
from mongoConnection import getMongoClient
from mongoAccess import *
#import logging

parser1 = reqparse.RequestParser()
parser1.add_argument('email')
parser1.add_argument('key')
parser1.add_argument('username')
parser1.add_argument('password')

class AddUser(Resource):
	def post(self):
		
		#server = smtplib.SMTP('localhost', 587)
		server = smtplib.SMTP('localhost')
		#server.ehlo()
		#server.starttls(context = ssl.create_default_context())
		#server.ehlo()
		#server.login("warmupproject2@gmail.com", "dummyemail")


		args = parser1.parse_args()
		username = args['username']
		password = args['password']
		email = args['email']
		print("username: " + username + " password: " + password + " email: " + email)

		myclient = getMongoClient()
		mydb = myclient["Project"]
		mycol = mydb["users"]
		print("mycol: " + str(mycol))
		myquery = {"email": email}
		myquery2 = {"username": username}
		row1 = mycol.find_one(myquery)
		row2 = mycol.find_one(myquery2)

		if not row1 and not row2:
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
			#REFACTOR new entry in 'user'
#			mycol.insert_one(dataToInsert)
			upsertUser(dataToInsert)
			msg2 = "\nHello " + username + "!\n validation key: <" + dataToInsert['verificationCode'] + ">"
			msg = "\nHello " + username + "!\n Please click this link to\
			verify your account for Stack.\n http://130.245.171.188/verify?email=" + email + "&key=" + dataToInsert['verificationCode']
			server.sendmail("ubuntu@projectinstance.cloud.compas.cs.stonybrook.edu", email, msg2)
			print("SENT MAIL SUCCESSFULY\n")
			server.quit()
			return jsonify(status="OK")
		else:
			return make_response(jsonify(status="error", error="Account already exists!"), 400)
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('adduser.html'), headers)
class VerifyUser(Resource):
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('verify.html'), headers)
	def post(self):
		if request.is_json:
			json = request.get_json()

		email = json['email']
		key = json['key']
		#myclient = getMongoClient()
		#mydb = myclient["Project"]
		#mycol = mydb["users"]
		#myquery = {"email" : email}
		#row = mycol.find_one(myquery)
		row = getUserByEmail(email)
		if not row:
			print("email not found")
			return make_response(jsonify(status="error", error="Email not found!"), 400)
		else:
			if row['validated'] is False and row['verificationCode'] == key:
				print("\n VALIDATED WITH CODE")
				#REFACTOR update 'validated' in 'user'
				#mycol.update_one(myquery, { "$set": { "validated" : True} })
				row['validated'] = True
				upsertUser(row)
				return jsonify(status="OK")
			elif row['validated'] is False and key == 'abracadabra':
				print("\n VALIDATED SUCCESSFULLY WITH BACKDOOR")
				#REFACTOR update 'validated' in 'user'
				#mycol.update_one(myquery, { "$set": { "validated" : True} })
				row['validated'] = True
				upsertUser(row)

				return jsonify(status="OK")
			else:
				print("\nVALIDATION ERROR")
				return make_response(jsonify(status="error", error="VerificationCode doesn't match or user is already validated!"), 400)

			





def getKey():
	randomk = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(16)])
	return randomk
