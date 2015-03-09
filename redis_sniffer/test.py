__author__ = 'jesse'
import redis

red = redis.Redis('127.0.0.1', 6379)

red.setex('test_key1', 'blahblah', 86400)
