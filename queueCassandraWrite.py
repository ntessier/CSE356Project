import pika
#import cassandra session
#from mediaAccess import getCassandraSession
import base64
def queueCassandraWrite(id, image, imagetype):
	connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.122.16'))
	channel = connection.channel()
	channel.queue_declare(queue='cassandraWrites', durable=True)
	encoded_image_string = base64.b64encode(image.read()).decode()
	#print(encoded_image_string)
	#print(type(encoded_image_string))
	message = id + '@@@' + encoded_image_string + '@@@' + imagetype
	channel.basic_publish(exchange = "", routing_key='cassandraWrites', body = message,properties = pika.BasicProperties(delivery_mode=2))
	connection.close()
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