import pika
from mongoConnection import getMongoClient
from bson.json_util import dumps
#import json
 
def queueWrite(collection, document):
	connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.122.10'))
	channel = connection.channel()
	channel.queue_declare(queue='mongoWrites', durable=True)
	message = collection + '@@@' + dumps(document)
	channel.basic_publish(exchange = "",routing_key='mongoWrites',body = message, properties = pika.BasicProperties(delivery_mode=2))
	connection.close()
def callback(ch,method,properties, body):
	body = body.decode('utf-8')
	#items = body.split('@@@')
	#collection = items[0]
	#document = json.loads(items[1])
	#connect to mongo db / collection
	
	ch.basic_ack(delivery_tag = method.delivery_tag)
def dequeueWrite():
	connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
	channel = connection.channel()
	channel.queue_declare(queue='mongoWrites', durable=True)
	channel.basic_consume(queue='mongoWrites', on_message_callback=callback)
	channel.start_consuming()

