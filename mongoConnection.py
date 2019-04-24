import pymongo
myclient = None
def getMongoClient():
	global myclient
	if not myclient:
		myclient = pymongo.MongoClient("mongodb://192.168.122.10:27017/")
	return myclient
	

