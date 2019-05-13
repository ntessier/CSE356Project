import pymongo
myclient = None
def getMongoClient():
	global myclient
	if not myclient:
		myclient = pymongo.MongoClient("mongodb://130.245.171.185:27017/")
	return myclient
	

