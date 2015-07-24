# Redis Sniffer v1.1.1

## About

This tool will monitor a specific port and interface for redis traffic and captures the commands being sent to Redis and/or formatted full TCP dump data.  This can be used for analysis for debugging or for replaying the transactions as a way of doing real load/performance testing.

Redis Hound must be run locally on a Redis server or a server that is sending commands to Redis.

## Installation
Installing from the Eternal Projects Apt repo is the preferred method of installation since it handles installing all the needed dependencies.

Once Redis Sniffer is installed, you will have the executable at /usr/local/bin/redis-sniffer

### Install from Apt
1. Get the key for the repo
```bash
wget -O - http://apt.eternalprojects.com/conf/apt.eternalprojects.com.gpg.key|apt-key add -
```
2. Add the Repo to /etc/apt/sources.list
```bash
deb http://apt.eternalprojects.com/ stable main
```
3. Install the package
```bash
sudo apt-get update
sudo apt-get install -y redis-sniffer
```

### Install from Pypi
```bash
sudo apt-get -y libpcap-dev python-dev
sudo pip install pypcap
sudo pip install dpkt
sudo pip install redis-sniffer
```

### Get the source and install

```bash
sudo apt-get -y install libpcap-dev python-dev
git clone https://github.com/eternalprojects/redis-sniffer.git
cd redis-sniffer
sudo python setup.py install
sudo python setup.py install --user
```


## Usage

**Please Note: Redis Sniffer must be run as root/sudo since it has to bind to a network interface which is not allowed by non-privileged users.**
```bash
sudo redis-sniffer -i <interface> -p <port>

sudo redis-sniffer -i bond0 -p 6379 -f setex,select,del
```
Additional Options:
```bash
-l {event,full,both} - logging type
--out - location to write logs
--event-log - name of the event log
--full-log - name of the full log
-f, --filter - specify a comma seperated list of redis commands to log
--extra - log any additional non-redis events that make it to the redis server
```
