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


class Sniffer:
    re_args = re.compile('\*\d+')
    re_lens = re.compile('\$\d+')
    port=None
    src_ip = None
    dst_ip = None
    logger = None


    def __init__(self):
        return

    @staticmethod
    def version():
        return 'v1.1.0'

    @staticmethod
    def set_filters(port):
        _filter = 'tcp port %s' % port
        if Sniffer.src_ip:
            _filter += ' and src %s' % Sniffer.src_ip
        if Sniffer.dst_ip:
            _filter += ' and dst %s' % Sniffer.dst_ip
        return _filter

    @staticmethod
    def get_client(ip_pkt, tcp_pkt):
        src = socket.inet_ntoa(ip_pkt.src)
        sport = tcp_pkt.sport
        dst = socket.inet_ntoa(ip_pkt.dst)
        dport = tcp_pkt.dport
        src_addr = '%s:%s' % (src, sport)
        dst_addr = '%s:%s' % (dst, dport)
        if sport == Sniffer.port:
            logging.debug("Data is a redis response")
            receiving = False
            client = dst_addr
        else:
            logging.debug("Data is a redis request")
            receiving = True
            client = src_addr
        return client, receiving

    @staticmethod
    def process_commands(client, n_args, n_parts, _parts):
        if n_parts == 1:
            logging.debug("Complete single command {} ".format(_parts[0]))
            return _parts[0]
        if (n_args * 2 + 1) == n_parts and int(_parts[-2][1:]) == len(_parts[-1]):
            # Complete normal command
            command = ' '.join([c for (i, c) in enumerate(_parts[1:]) if i % 2 == 1])
            return command
        else:
            if _parts[2] == 'MULTI':
                if _parts[-1] == 'EXEC':
                    # Complete MULTI command
                    _multi_parts = _parts[2:]
                    _partial = []
                    _n_args = 1
                    for _part in _multi_parts:
                        if Sniffer.re_args.match(_part):
                            _n_args = int(_part[1:])
                            continue
                        if Sniffer.re_lens.match(_part):
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
                    # Partial MULTI command
                    return False
            else:
                # Partial normal command
                return False

    @staticmethod
    def sniff(interface, port=6379, debug=False):
        Sniffer.port = port
        pc = pcap.pcap(interface)
        pc.setfilter(Sniffer.set_filters(port))

        receiving = False
        receiving_partials = {}
        request_sizes = defaultdict(int)
        sessions = {}

        logging.debug("<=============== Checking for Ethernet Packets ==============>")

        for ptime, pdata in pc:
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
            client, receiving = Sniffer.get_client(ip_pkt, tcp_pkt)

            if receiving:
                # request
                if not tcp_data:
                    continue
                _parts = tcp_data.splitlines()
                _receiving_partial = receiving_partials.get(client, [])
                _parts = _receiving_partial + _parts
                request_sizes[client] += len(pdata)
                request_size = request_sizes[client]
                n_parts = len(_parts)
                logging.debug("Check to ensure the packets contain valid redis commands")
                try:
                    n_args = int(_parts[0][1:])
                except ValueError:
                    logging.debug("Inline redis command: {}".format(' '.join(_parts)))
                    logging.debug(client)
                    n_args = 0

                command = Sniffer.process_commands(client, n_args, n_parts, _parts)
                if command:
                    receiving_partials.pop(client, None)
                    request_sizes.pop(client, None)
                else:
                    receiving_partials[client] = _parts
                    continue

                stat = sessions.pop(client, None)
                if stat:
                    _request_size = stat.get('request_size', 0)
                    _response_size = stat.get('response_size', 0)
                    _command = stat['command']
                    yield ptime, client, _request_size, _response_size, _command

                sessions[client] = {'command': command, 'request_size': request_size}
            else:
                session = sessions.get(client)
                if not session:
                    logging.debug("request not captured, drop its response")
                    continue
                if session.get('response_size'):
                    session['response_size'] += len(pdata)
                else:
                    session['response_size'] = len(pdata)
                    # TODO: write logger message buffer to file


