from mongoConnection import getMongoClient
import random
import string
from project import custom_validator
from cassandra.cluster import Cluster
from flask import request, Response, make_response, render_template
from flask_restful import Resource
from flask import jsonify
from queueCassandraWrite import queueCassandraWrite

from flask_jwt_extended import JWTManager
from flask_jwt import JWT, jwt_required, current_identity
from flask_jwt_extended.tokens import decode_jwt
from flask_jwt_extended.utils import has_user_loader, user_loader

from flask_jwt_extended import (jwt_optional, verify_jwt_in_request, set_access_cookies, set_refresh_cookies, unset_jwt_cookies, create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import pymongo
from flask_jwt_extended.view_decorators import _decode_jwt_from_request
from flask_jwt_extended.exceptions import NoAuthorizationError

#TODO: remover vvv

def getCassandraSession():
	cluster = Cluster(['192.168.122.16'])
	session = cluster.connect('media')
	return session
def generateNewMediaID(): #will generate random integer ID while avoiding collisions
	randomkey= ''.join([random.choice(string.digits) for n in range(16)])
	session = getCassandraSession()
	id_lookup_stmt = session.prepare("SELECT COUNT(*) as coun FROM images WHERE id=?")
	coun = session.execute(id_lookup_stmt, [randomkey])
	#print('coun = ' + str(coun[0]))
	while coun[0].coun != 0:
		randomkey = ''.join([random.choice(string.digits) for n in range(16)])
		coun = session.execute(id_lookup_stmt, [randomkey])
	return randomkey

#TODO: queue this?
class AddMedia(Resource):
	#@custom_validator
	def post(self):
		error_out=False
		try:
			verify_jwt_in_request()
		except NoAuthorizationError:
			#return jsonify(status="error", error="not logged in")
			#request.headers.get('content-length')
			#response = Response()
			#response.headers.add('content-length', '71')
			error_out = True
			print("plan to error out")
		#if error_out:
			#return jsonify(status="OK", id=id)
		
		#username = get_jwt_identity()
		#if username is None:
		#print(username)	
		#	return make_response(jsonify(status = "error", error = "not logged in"), 400)
		#print(request.headers)
		#for cookie in request.cookies:
		#	print("COOKIE FOUND FOR MEDIA: ", cookie)
		print("MADE IT INTO ADDMEDIA")
		#if request.is_json:
		#	json = request.get_json()
		#else:
		#	return make_response(jsonify(status="error", error ="request is not json"), 400)
		#content = json['content']
		file = request.files['content']
		filetype = file.content_type
		#file = file.read()
		#print(type(file))
	#	print('grabbed file')
		#session = getCassandraSession()
	#	print('grabbed session')
			#	print('generated ID')
		if error_out:
			return make_response(jsonify(status="error", error="not logged in"), 400)
		print("QUEUING A CASSANDRA WRITE")
		if file is None:
			return make_response(jsonify(status="error", error="No file attached!"), 400)
		if filetype is None:
			return make_response(jsonify(status="error", error="No filetype!"), 400)
		id = generateNewMediaID()
		queueCassandraWrite(id, file, filetype)

		client = getMongoClient()
		db = client["Project"]
		media_col = db["media"]
		dToInsert = {}
		dToInsert["media_id"] = id
		dToInsert["object_id"] = None
		dToInsert["username"] = get_jwt_identity()
		media_col.insert_one(dToInsert)

		#session.execute("INSERT INTO images(id, contents, contenttype) VALUES (%s, %s, %s)", (id, file, filetype))
	#	print("made it past inserting into database")
		
		return jsonify(status="OK", id=id)
	def get(self):
		headers = {'Content-Type' : 'text/html'}
		return make_response(render_template('addmedia.html'), headers)

class GetMedia(Resource):
	def get(self, id):
		#check memcache before querying database
		session = getCassandraSession()
		rows = session.execute("SELECT id, contents, contenttype FROM images where id = %s", [id])
		row = rows[0]
		if row is None:
			return make_response(jsonify(status="error", message="No media found with that id!"), 400)
		#r = Response(response = row.contents, status=200, mimetype = row.contenttype)
		r = make_response(row.contents)
		r.headers['Content-Type'] = row.contenttype
		return r

#remove a media file from the database based on a given ID
#TODO: queue this somehow
def removeMediaByID(media_id):

		
	client = getMongoConnection()		
	db = client["Project"]
	col = db["media"]
	my_media = col.find({"media_id": media_id})
	if not my_media:
		return "error"

	col.delete_one({"media_id": media_id})
	session = getCassandraSession()
	session.execute("DELETE FROM images WHERE id = %s", [media_id])
	return "OK"
#from project import custom_validator

