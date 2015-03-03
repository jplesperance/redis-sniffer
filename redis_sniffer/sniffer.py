#!/usr/bin/env python

""" A redis query sniffer
"""

import re
import sys
import socket
import signal
import argparse
from collections import defaultdict

import pcap
import dpkt

re_args = re.compile('\*\d+')
re_lens = re.compile('\$\d+')


def signal_handler(signal, frame):
    sys.exit(0)


def sniff(interface, port=6379, src_ip=None, dst_ip=None):
    """Sniff Redis queries and responses

    *interface* is network interface name or raw packets file record with
    tcpdump::

        tcpdump -i <interface> -s 65535 tcp port <port> -w <redis.pcap>

    *port* is port of the redis server
    """

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

            signal.signal(signal.SIGINT, signal_handler)
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help="the interface to bind to")
    parser.add_argument('-p', '--port', type=int, help="the port to grab packets from.  Default: 6379", default=6379)
    parser.add_argument('--out', help="the location to generate the full or event logs, defaults to the directory the application is executed from")
    parser.add_argument('-l', choices=['both', 'event', 'full'], default='both', help="the type of log(s) you want to create. Default: both")
    parser.add_argument('--event-log', default="event_sniff", help="the name of the event outout file. Default: event_sniff")
    parser.add_argument('--full-log', default="full_sniff", help="the name of the full sniff output file. Default: full_sniff")
    args = parser.parse_args()
    fmt_full = '%.6f %-21s %8d %8d %s\n'
    fmt = '%s\n'
    path = ""
    if args.out:
        path = args.out
    if args.l == 'both':
        full_output = open(path + args.full_log, 'w')
        event_output = open(path + args.event_log, 'w')
    elif args.l == 'full':
        full_output = open(path + args.full_log, 'w')
    elif args.l == 'event':
        event_output = open(path + args.event_log, 'w')
    for session in sniff(args.interface, args.port):
        ptime, client, req_size, resp_size, command = session
        if args.l == 'event':
            event_output.write(fmt % (command))
        elif args.l == 'full':
            full_output.write(fmt_full % (ptime, client, req_size, resp_size, command))
        else:
            event_output.write(fmt % (command))
            full_output.write(fmt_full % (ptime, client, req_size, resp_size, command))

if __name__ == '__main__':
    main()
