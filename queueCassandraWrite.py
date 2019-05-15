import pika
#import cassandra session
#from mediaAccess import getCassandraSession
import base64
import time
channel = None
connection = None
def queueCassandraWrite(id, image, imagetype):
	start = time.time()

	global connection
	global channel
	if connection is None or connection.is_closed:
		connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.122.38', heartbeat=0))
	if channel is None or channel.is_closed:
		channel = connection.channel()
	channel.queue_declare(queue='cassandraWrites', durable=True)
	encoded_image_string = base64.b64encode(image.read()).decode()
	#print(encoded_image_string)
	#print(type(encoded_image_string))
	message = id + '@@@' + encoded_image_string + '@@@' + imagetype
	pub_start = time.time()
	channel.basic_publish(exchange = "", routing_key='cassandraWrites', body = message,properties = pika.BasicProperties(delivery_mode=2))
	print("CASSANDRAPUB: ", time.time() - pub_start) 
	#connection.close()
	print("CASSANDRACON: ", time.time() - start)
#def callback(ch,method, properties, body):
	#in callback, access the cassadnra database and insert the body into it...
	#this takes place in the cassandra instance
#	session = getCassandraSession()
#	body = body.decode('utf-8')
#	items = body.split('@@@')
#	id = items[0]
#	image = items[1]
#	imagetype = items[2]
#	session.execute("INSERT INTO images(id, contents, contenttype) VALUES (%s, %s, %s)", (id, image, imagetype))
#	ch.basic_ack(delivery_tag = method.delivery_tag)

#def dequeueWrite():
#	connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
#	channel = connection.channel()
#	channel.queue_declare(queue='cassandraWrites', durable=True)
#	channel.basic_consume(queue='cassandraWrites', on_message_callback=callback)
