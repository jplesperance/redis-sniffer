# Redis Sniffer v1.0.0

## About

This sniffer is based on http://github.com/xupeng/redis-sa

This tool will monitor a specific port and interface for redis traffic and captures the commands being sent to Redis and/or formatted full TCP dump data.  This can be used for analysis for debugging or for replaying the transactions as a way of doing real load/performance testing.

Redis Sniffer must be run locally on a Redis server.

## Installation

### Dependencies

There are 2 dependencies for Redis Sniffer
1. pypcap - This will need to be installed globally and for the current user if desired
```bash
sudo pip install pypcap
pip install pypcap
```
2. dpkt - Installed as part of the build process

### Get the source and install

```bash
git clone https://github.com/jplesperance/redis-sa.git
cd redis-sa
sudo python setup.py install
sudo python setup.py install --user
```
Since the setup script will create an egg file, it will be installed as a pip module

### Usage

**Please Note: Redis Sniffer must be run as root/sudo since it has to bind to a network interface which is not allowed by non-privileged users.**
```bash
sudo redis-sa -i <interface> -p <port>
```

The captured Redis traffic will be logged to 2 different files
1. full_output - This will be a formatted version of the pcap data that includes: process time, the client, request size, response size and the command
2. comm_output - This is just a list of all the Redis commands captured by Redis Sniffer.  Each line in this file could be replayed without modification for simulated load testing/performance testing/tuning
