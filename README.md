# Redis Sniffer v1.1.1
[![PyPI version](https://badge.fury.io/py/redis-sniffer.svg)](http://badge.fury.io/py/redis-sniffer) [![Requirements Status](https://requires.io/github/jplesperance/redis-sniffer/requirements.svg?branch=bugfix%2FRS-1-allow-capture-of-non-redis-traffic)](https://requires.io/github/jplesperance/redis-sniffer/requirements/?branch=bugfix%2FRS-1-allow-capture-of-non-redis-traffic)  [![Build Status](https://travis-ci.org/jplesperance/redis-sniffer.svg?branch=bugfix%2FRS-1-allow-capture-of-non-redis-traffic)](https://travis-ci.org/jplesperance/redis-sniffer.svg?branch=bugfix%2FRS-1-allow-capture-of-non-redis-traffic) [![Code Climate](https://codeclimate.com/github/jplesperance/redis-sniffer/badges/gpa.svg)](https://codeclimate.com/github/jplesperance/redis-sniffer) [![codecov.io](http://codecov.io/github/jplesperance/redis-sniffer/coverage.svg?branch=master)](http://codecov.io/github/jplesperance/redis-sniffer?branch=master)

## About

This tool will monitor a specific port and interface for redis traffic and captures the commands being sent to Redis and/or formatted full TCP dump data.  This can be used for analysis for debugging or for replaying the transactions as a way of doing real load/performance testing.

All installation and usage documentation are now located at: https://redis-sniffer.readme.io/docs/getting-started
