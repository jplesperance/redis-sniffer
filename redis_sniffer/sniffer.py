#!/usr/bin/env python

""" A redis query sniffer
"""

import re
import socket
from collections import defaultdict

import pcap
import dpkt
from redis_sniffer.log import Log
import logging

RE_ARGS = re.compile('\*\d+')
RE_LENS = re.compile('\$\d+')

class Sniffer:
    def __init__(self, source, port=6379, src_ip=None, dst_ip=None, replay=False):
        self.port = port
        if replay:
            self.packet_iterator = replay_iterator(source, port, src_ip, dst_ip)
        else:
            self.packet_iterator = live_iterator(source, port, src_ip, dst_ip)

    @staticmethod
    def version():
        return 'v1.1.0'

    def get_client(self, ip_pkt, tcp_pkt):
        src = socket.inet_ntoa(ip_pkt.src)
        sport = tcp_pkt.sport
        dst = socket.inet_ntoa(ip_pkt.dst)
        dport = tcp_pkt.dport
        src_addr = '%s:%s' % (src, sport)
        dst_addr = '%s:%s' % (dst, dport)
        if sport == self.port:
            logging.debug("Data is a redis response")
            receiving = False
            client = dst_addr
        else:
            logging.debug("Data is a redis request")
            receiving = True
            client = src_addr
        return client, receiving

    def process_commands(self, n_args, _parts):
        n_parts = len(_parts)

        if n_parts == 1:
            logging.debug("Complete single command {} ".format(_parts[0]))
            return _parts[0]
        # TODO: pipelined requests :(
        # TODO: check for null as last element
        if (n_args * 2 + 1) == n_parts and int(_parts[-2][1:]) == len(_parts[-1]):
            logging.debug("Complete normal command")
            command = ' '.join([c for (i, c) in enumerate(_parts[1:]) if i % 2 == 1])
            return command
        else:
            if _parts[2] == 'MULTI':
                if _parts[-1] == 'EXEC':
                    logging.debug("Complete MULTI command")
                    _multi_parts = _parts[2:]
                    _partial = []
                    _n_args = 1
                    for _part in _multi_parts:
                        if RE_ARGS.match(_part):
                            _n_args = int(_part[1:])
                            continue
                        if RE_LENS.match(_part):
                            continue
                        if _n_args > 0:
                            _partial.append(_part)
                            _n_args -= 1
                            if _n_args == 0 and _part != 'EXEC':
                                _partial.append('/')
                            continue
                    command = ' '.join(_partial)
                    return command
                else:
                    logging.debug("Partial MULTI command")
                    return False
            else:
                logging.debug("Partial normal command")
                return False

    def sniff(self):
        receiving = False
        receiving_partials = {}
        request_sizes = defaultdict(int)
        sessions = {}

        logging.debug("<=============== Checking for Ethernet Packets ==============>")

        for ptime, pdata in self.packet_iterator:
            ether_pkt = dpkt.ethernet.Ethernet(pdata)
            ip_pkt = ether_pkt.data
            tcp_pkt = ip_pkt.data
            tcp_data = tcp_pkt.data

            logging.debug("Checking the length of the tcp packet")

            if len(tcp_data) == 0:
                logging.debug("TCP Packet is empty")
                continue

            logging.debug("TCP Packet has data")
            logging.debug("Checking to see if the data is a request or response")
            client, receiving = self.get_client(ip_pkt, tcp_pkt)

            if receiving:
                # request
                # TODO: why is this check here?
                if not tcp_data:
                    continue

                request_sizes[client] += len(pdata)
                data = receiving_partials.get(client, '') + tcp_data

                if data[-2:] != '\r\n':
                    logging.debug("Command not CRLF terminated. Add to partial and continue.")
                    receiving_partials[client] = data
                    continue

                # Ensure that if the CRLF is split between requests that the "newline" isn't double counted
                _parts = data.splitlines()

                logging.debug("Check to ensure the packets contain valid redis commands")
                try:
                    n_args = int(_parts[0][1:])
                except ValueError:
                    if n_parts == 1:
                        logging.debug("Inline redis command: {}".format(' '.join(_parts)))
                        n_args = 0
                    else:
                        logging.warn("Unknown packet")
                        logging.debug(data)
                        receiving_partials.pop(client, None)
                        request_sizes.pop(client, None)
                        continue

                command = self.process_commands(n_args, _parts)
                if command:
                    receiving_partials.pop(client, None)
                    request_size = request_sizes.pop(client, 0)

                    # All responses must have been collected. Yield the previous session before overwriting
                    stat = sessions.pop(client, None)
                    if stat:
                        _request_size = stat.get('request_size', 0)
                        _response_size = stat.get('response_size', 0)
                        _command = stat['command']
                        yield ptime, client, _request_size, _response_size, _command

                    sessions[client] = {'command': command, 'request_size': request_size}
                else:
                    # Couldn't resolve command, stash all the data in the dict until the next packet is found
                    receiving_partials[client] = data
            else:
                session = sessions.get(client)
                if not session:
                    logging.debug("request not captured, drop its response")
                    continue
                if session.get('response_size'):
                    session['response_size'] += len(pdata)
                else:
                    session['response_size'] = len(pdata)

def replay_iterator(pcap, redis_port=6379, src_ip=None, dst_ip=None):
    from scapy.all import PcapReader
    import itertools
    reader = PcapReader(pcap)

    def packet_filter(p):
        return (p.payload.sport == redis_port or p.payload.dport == redis_port) and \
               (src_ip == None or src_ip == p.payload.src) and \
               (dst_ip == None or dst_ip == p.payload.dst)

    def map_to_pcap(p):
        return p.time, p.original

    return itertools.imap(map_to_pcap, itertools.ifilter(packet_filter, reader))

def live_iterator(interface, redis_port=6379, src_ip=None, dst_ip=None):
    filter = 'tcp port %s' % redis_port
    if src_ip:
        filter += ' and src %s' % src_ip
    if dst_ip:
        filter += ' and dst %s' % dst_ip

    pc = pcap.pcap(interface)
    pc.setfilter(filter)

    return pc

