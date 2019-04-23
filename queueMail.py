import smtplib
import pika
def queueMail(receiver, msg):	#server = smptlib.SMTP('localhost')
	#print("Entered QueueMail")
#need to give to rabbit consumer the message to send, and the receiver of the email
	connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
	channel = connection.channel()
	channel.queue_declare(queue='mail', durable=True)
	channel.basic_publish(exchange="", routing_key='mail', body = receiver + '@@' + msg)
	connection.close() 
	#print("Reached end of QueueMail, Receiver and msg: " + receiver + ' ' + msg)
def callback(ch, method, properties, body):
	server = smtplib.SMTP('localhost')
	body = body.decode("utf-8")
	#print("Entered callback, body is: " + body)
	listOfInfo = body.split('@@')
	receiver = listOfInfo[0]
	#print("Receiver in callback is " + receiver)
	msgToSend = listOfInfo[1]
	#print("Msg to send in callback is " + msgToSend)
	server.sendmail("ubuntu", receiver, msgToSend)
	server.quit()
def dequeueMail():
	connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
	channel = connection.channel()
	channel.queue_declare(queue='mail', durable=True)
	channel.basic_consume(queue='mail', auto_ack=True, on_message_callback=callback)
	#print("we started consuming in dequeueMail")		
	channel.start_consuming()



		
