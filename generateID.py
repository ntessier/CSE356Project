from mongoConnection import getMongoClient
import random
import string

def generateNewID(): #will generate random integer ID while avoiding collisions
	randomkey= ''.join([random.choice(string.digits) for n in range(16)])
	client = getMongoClient()
	queryForID = {"id" : int(randomkey)}
	db = client["Project"]
	answerCol = db['answers']
	questionCol = db['questions']
	while answerCol.count(queryForID) != 0 or questionCol.count(queryForID) != 0:
		randomkey = ''.join([random.choice(string.digits) for n in range(16)])
		queryForID = {"id" : int(randomkey)}
	print(str(randomkey))
	return randomkey
if __name__ == '__main__':
	generateNewID()
