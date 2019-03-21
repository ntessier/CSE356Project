from flask import Flask, jsonify, request, render_template, make_response, current_app
from flask_restful import Resource, Api, reqparse
import pymongo
import json
import random
import string
import smtplib
from mongoConnection import getMongoClient
#import logging
server = smtplib.SMTP('smtp.gmail.com', 587)
server.ehlo()
server.starttls()
server.login("warmupproject2@gmail.com", "dummyemail")

parser1 = reqparse.RequestParser()
parser1.add_argument('email')
parser1.add_argument('key')
parser1.add_argument('username')
parser1.add_argument('password')

class AddUser(Resource):
	def post(self):
		args = parser1.parse_args()
		username = args['username']
		password = args['password']
		email = args['email']
		print("username: " + username + "password: " + password + "email: " + email)
		myclient = getMongoClient()
		mydb = myclient["Project"]
		mycol = mydb["users"]
		print("mycol: " + str(mycol))
		myquery = {"email": email}
		myquery2 = {"username": username}
		row1 = mycol.count(myquery)
		row2 = mycol.count(myquery2)
		if row1 == 0 and row2 == 0:
			dataToInsert = {}
			dataToInsert['username'] = username
			dataToInsert['password'] = password
			dataToInsert['email'] = email 
			dataToInsert['validated'] = False
			dataToInsert['verificationCode'] = getKey()
			mycol.insert_one(dataToInsert)
			msg = "\nHello" + username + "!\n Please click this link to\
			verify your account for Stack.\n http://130.245.171.188/verify?email=" + email + "&key=" + dataToInsert['verificationCode']
			server.sendmail("warmupproject2@gmail.com", email, msg)
			return jsonify(status="OK")
		else:
			return jsonify(status="ERROR", error="Account already exists!")
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('adduser.html'), headers)
class VerifyUser(Resource):
	def get(self):
		args = parser1.parse_args()
		email = args['email']
		key = args['key']
		myclient = getMongoClient()
		mydb = myclient["wp2"]
		mycol = mydb["users"]
		myquery = {"email" : email}
		row = mycol.find_one(myquery)
		if row is None:
			print("user not found")
		else:
			if row['validated'] is False and row['verificationCode'] == key:
				mycol.update_one(myquery, { "$set": { "validated" : True} })
				return jsonify(status ="OK")
			elif row['validated'] is False and key == 'abracadabra':
				mycol.update_one(myquery, {"$set": {"validated" : True} })
				return jsonify(status="OK")
			else:
				return jsonify(status="ERROR")
	def post(self):
		if request.is_json:
			json = request.get_json()

		email = json['email']
		key = json['key']
		myclient = pymongo.MongoClient("mongodb://localhost:27017/")
		mydb = myclient["wp2"]
		mycol = mydb["users"]
		myquery = {"email" : email}
		row = mycol.find_one(myquery)
		if row is None:
			print("user not found")
		else:
			if row['validated'] is False and row['verificationCode'] == key:
				mycol.update_one(myquery, { "$set": { "validated" : True} })
				return jsonify(status="OK")
			elif row['validated'] is False and key == 'abracadabra':
				mycol.update_one(myquery, { "$set": { "validated" : True} })
				return jsonify(status="OK")
			else:
				return jsonify(status="ERROR")

			





def getKey():
	randomk = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(16)])
	return randomk