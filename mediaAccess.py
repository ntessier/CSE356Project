import random
import string
from project import custom_validator
from cassandra.cluster import Cluster
from flask import request, Response, make_response
from flask_restful import Resource
from flask import jsonify
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
class AddMedia(Resource):
	@custom_validator
	def post(self):
		#if request.is_json:
		#	json = request.get_json()
		#else:
		#	return make_response(jsonify(status="error", error ="request is not json"), 400)
		#content = json['content']
		file = request.files['content']
		filetype = file.content_type
		file = file.read()
		print('grabbed file')
		session = getCassandraSession()
		print('grabbed session')
		id = generateNewMediaID()
		print('generated ID')
		session.execute("INSERT INTO images(id, contents, contenttype) VALUES (%s, %s, %s)", (id, file, filetype))
		print("made it past inserting into database")
		return jsonify(status="OK", id=id)
class GetMedia(Resource):
	def get(self, id):
		#check memcache before querying database
		session = getCassandraSession()
		rows = session.execute("SELECT id, contents, contenttype FROM images where id = %s", [id])
		row = rows[0]
		if row is None:
			return make_response(jsonify(status="error", message="No media found with that id!"), 400)
		row = rows[0]
		#r = Response(response = row.contents, status=200, mimetype = row.contenttype)
		r = make_response(row.contents)
		r.headers['Content-Type'] = row.contenttype
		return r

		
#from project import custom_validator

