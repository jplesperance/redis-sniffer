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

### Install from Pypi
```bash
sudo pip install redis-sniffer
```

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

### Get the source and install

```bash
git clone https://github.com/jplesperance/redis-sa.git
cd redis-sa
sudo python setup.py install
sudo python setup.py install --user
```
Since the setup script will create an egg file, it will be installed as a pip module

## Usage

**Please Note: Redis Sniffer must be run as root/sudo since it has to bind to a network interface which is not allowed by non-privileged users.**
```bash
sudo redis-sniffer -i <interface> -p <port>
```
Additional Options:
--log {event,full,both} - Logging type
--out  - Location to write logs
--event-log - name of the event log
--full-log - name of the full log
