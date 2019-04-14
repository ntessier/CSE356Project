from flask_restful import Resource, Api, reqparse
from flask import Flask, jsonify, request, render_template, make_response

import pika

app = Flask(__name__)
api = Api(app)


parser = reqparse.RequestParser()
parser.add_argument('keys')
parser.add_argument('key')
parser.add_argument('msg')
class Listen(Resource):
	def post(self):
		args = parser.parse_args()
		connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
		channel = connection.channel()
		result = channel.queue_declare(exclusive=True)
		queue_name = result.method.queue #if this doesnt work try setting queue=result instead
		keys = args['keys']
		for key in keys:
			channel.queue_bind(exchange='hw3', queue=queue_name, routing_key = key)

		channel.basic_consume(callback, queue=queue_name, no_ack=True)
		channel.start_consuming()
	def callback(ch, method, properties, body):
		#body = body.decode('utf-8')
		return jsonify(msg=str(body, 'utf-8'))
class Speak(Resource):
	def post(self):
		args = parser.parse_args()
		connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
		channel = connection.channel()
		channel.basic_publish(exchange='hw3', routing_key = args['key'], body = args['msg'])

api.add_resource(Speak, '/speak')
api.add_resource(Listen, '/listen')


		
if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True)
