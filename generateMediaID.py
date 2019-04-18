#from mongoConnection import getMongoClient
import random
import string

def generateNewMediaID(): #will generate random integer ID while avoiding collisions
        randomkey= ''.join([random.choice(string.digits) for n in range(16)])
	#TODO: query cassandra to make sure we dont have any ID collisions
	#if we don't we pass the ID back and we're good
         
#       print(str(randomkey))
        return randomkey
if __name__ == '__main__':
        generateNewMediaID()

