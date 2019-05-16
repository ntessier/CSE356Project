import pymongo
myclient = None
def getMongoClient():
	global myclient
	if not myclient:
		myclient = pymongo.MongoClient("mongodb://130.245.170.78:27017/")
	return myclient
	

