#!/usr/bin/env python

""" A redis query sniffer
"""

import re
import socket
from collections import defaultdict
import pcap

import dpkt


class Sniffer:
    re_args = re.compile('\*\d+')
    re_lens = re.compile('\$\d+')

    def __init__(self):
        return

    @staticmethod
    def sniff(interface, port=6379, src_ip=None, dst_ip=None):

        pc = pcap.pcap(interface)
        _filter = 'tcp port %s' % port
        if src_ip:
            _filter += ' and src %s' % src_ip
        if dst_ip:
            _filter += ' and dst %s' % dst_ip
        pc.setfilter(_filter)

        receiving = False
        receiving_partials = {}
        request_sizes = defaultdict(int)
        sessions = {}
        for ptime, pdata in pc:
            ether_pkt = dpkt.ethernet.Ethernet(pdata)
            ip_pkt = ether_pkt.data
            tcp_pkt = ip_pkt.data
            tcp_data = tcp_pkt.data

            if len(tcp_data) == 0:
                continue

            src = socket.inet_ntoa(ip_pkt.src)
            sport = tcp_pkt.sport
            dst = socket.inet_ntoa(ip_pkt.dst)
            dport = tcp_pkt.dport
            src_addr = '%s:%s' % (src, sport)
            dst_addr = '%s:%s' % (dst, dport)
            if sport == port:
                receiving = False
                client = dst_addr
            else:
                receiving = True
                client = src_addr

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
                n_args = int(_parts[0][1:])
                if (n_args * 2 + 1) == n_parts and int(_parts[-2][1:]) == len(_parts[-1]):
                    # Complete normal command
                    command = ' '.join([c for (i, c) in enumerate(_parts[1:]) if i % 2 == 1])
                    receiving_partials.pop(client, None)
                    request_sizes.pop(client, None)
                else:
                    if _parts[2] == 'MULTI':
                        if _parts[-1] == 'EXEC':
                            # Complete MULTI command
                            _multi_parts = _parts[2:]
                            _partial = []
                            _n_args = 1
                            for _part in _multi_parts:
                                if re_args.match(_part):
                                    _n_args = int(_part[1:])
                                    continue
                                if re_lens.match(_part):
                                    continue
                                if _n_args > 0:
                                    _partial.append(_part)
                                    _n_args -= 1
                                    if _n_args == 0 and _part != 'EXEC':
                                        _partial.append('/')
                                    continue
                            command = ' '.join(_partial)
                            receiving_partials.pop(client, None)
                            request_sizes.pop(client, None)
                        else:
                            # Partial MULTI command
                            receiving_partials[client] = _parts
                            continue
                    else:
                        # Partial normal command
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
                    # request not captured, drop its response
                    continue
                if session.get('response_size'):
                    session['response_size'] += len(pdata)
                else:
                    session['response_size'] = len(pdata)



