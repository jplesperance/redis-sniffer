__author__ = 'jesse'
import redis

red = redis.Redis('127.0.0.1', 6379)

i=1
while True:
	red.setex('test_key'+str(i), 'blahblah', 86400)
