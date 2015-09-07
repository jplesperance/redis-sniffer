#!/usr/bin/env python

""" A redis query sniffer
"""

import re
import socket
from collections import defaultdict

import pcap
import dpkt
from redis_sniffer.log import Log


class Sniffer:
    re_args = re.compile('\*\d+')
    re_lens = re.compile('\$\d+')
    src_ip = None
    dst_ip = None
    debug = False
    logger = None
    debugMsg = []


    def __init__(self):
        return

    @staticmethod
    def version():
        return 'v1.1.0'

    @staticmethod
    def set_src_ip(ip):
        Sniffer.src_ip = ip

    @staticmethod
    def set_dst_ip(ip):
        Sniffer.dst_ip = ip

    @staticmethod
    def set_debug(debug):
        Sniffer.debug = debug

    @staticmethod
    def set_filters(port):
        _filter = 'tcp port %s' % port
        if Sniffer.src_ip:
            _filter += ' and src %s' % Sniffer.src_ip
        if Sniffer.dst_ip:
            _filter += ' and dst %s' % Sniffer.dst_ip
        return _filter

    @staticmethod
    def set_client(ip_pkt, tcp_pkt):
        src = socket.inet_ntoa(ip_pkt.src)
        sport = tcp_pkt.sport
        dst = socket.inet_ntoa(ip_pkt.dst)
        dport = tcp_pkt.dport
        src_addr = '%s:%s' % (src, sport)
        dst_addr = '%s:%s' % (dst, dport)
        if sport == port:
            Sniffer.debugMsg.append("Data is being sent")
            receiving = False
            client = dst_addr
        else:
            Sniffer.debugMsg.append("Data is being received")
            receiving = True
            client = src_addr
        return client

    @staticmethod
    def getDebugLogger():
        if None in Sniffer.logger:
            Sniffer.logger = Log('debug', "./", {'debug': 'rs_debug'})

    @staticmethod
    def process_commands(client, n_args, n_parts, _parts):
        if (n_args * 2 + 1) == n_parts and int(_parts[-2][1:]) == len(_parts[-1]):
            # Complete normal command
            command = ' '.join([c for (i, c) in enumerate(_parts[1:]) if i % 2 == 1])
            Sniffer.receiving_partials.pop(client, None)
            Sniffer.request_sizes.pop(client, None)
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
                    Sniffer.receiving_partials.pop(client, None)
                    Sniffer.request_sizes.pop(client, None)
                    return command
                else:
                    # Partial MULTI command
                    Sniffer.receiving_partials[client] = _parts
                    return False
            else:
                # Partial normal command
                Sniffer.receiving_partials[client] = _parts
                return False

    @staticmethod
    def sniff(interface, port=6379, debug=False):

        pc = pcap.pcap(interface)
        pc.setfilter(Sniffer.set_filters(port))

        receiving = False
        Sniffer.receiving_partials = {}
        request_sizes = defaultdict(int)
        sessions = {}

        Sniffer.debugMsg.append("<=============== Checking for Ethernet Packets ==============>")

        for ptime, pdata in pc:
            ether_pkt = dpkt.ethernet.Ethernet(pdata)
            ip_pkt = ether_pkt.data
            tcp_pkt = ip_pkt.data
            tcp_data = tcp_pkt.data

            Sniffer.debugMsg.append("Checking the length of the tcp packet")

            if len(tcp_data) == 0:
                Sniffer.debugMsg.append("TCP Packet is empty")
                continue

            Sniffer.debugMsg.append("TCP Packet has data")
            Sniffer.debugMsg.append("Checking to see if the data is being sent or received")
            client = Sniffer.get_client(ip_pkt, tcp_pkt)

            if receiving:
                # request
                if not tcp_data:
                    continue
                _parts = tcp_data.splitlines()
                _receiving_partial = Sniffer.receiving_partials.get(client, [])
                _parts = _receiving_partial + _parts
                Sniffer.request_sizes[client] += len(pdata)
                request_size = Sniffer.request_sizes[client]
                n_parts = len(_parts)
                Sniffer.debugMsg.append("Check to ensure the packets contain valid redis commands")
                try:
                    n_args = int(_parts[0][1:])
                except ValueError:
                    continue

                command = Sniffer.process_commands(client, n_args, n_parts, _parts)
                if command == False:
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
                    Sniffer.debugMsg.append("request not captured, drop its response")
                    continue
                if session.get('response_size'):
                    session['response_size'] += len(pdata)
                else:
                    session['response_size'] = len(pdata)
                    # TODO: write logger message buffer to file


