def getMongoClient():
        import pymongo
        myclient = pymongo.MongoClient("mongodb://192.168.122.10:27017/")
       	return myclient

