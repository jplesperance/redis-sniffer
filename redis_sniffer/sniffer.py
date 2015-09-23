#!/usr/bin/env python

""" A redis query sniffer
"""

import re
import socket

import hiredis
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
            is_request = False
            client = dst_addr
        else:
            logging.debug("Data is a redis request")
            is_request = True
            client = src_addr
        return client, is_request

    def sniff(self):
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
                logging.debug("extra bytes: %s", len(pdata))
                continue

            logging.debug("TCP Packet has data")
            logging.debug("Checking to see if the data is a request or response")
            client, is_request = self.get_client(ip_pkt, tcp_pkt)

            if is_request:
                # TODO: why is this check here?
                if not tcp_data:
                    logging.debug("TCP Data is empty")
                    logging.debug("extra bytes: %s", len(pdata))
                    continue

                session = sessions.get(client, None)
                if not session:
                    logging.debug("Creating a new session for %s", client)
                    session = RedisSession()
                    sessions[client] = session

                if session.is_receiving() and session.commands:
                    yield ptime, client, session.request_size, session.response_size, ' / '.join(session.commands)
                    session.clear()

                session.process_request_packet(len(pdata), tcp_data)

            else:
                session = sessions.get(client)
                if not session:
                    logging.debug("No session for %s. Drop unknown response",client)
                    logging.debug("extra bytes: %s", len(pdata))
                    continue

                session.process_response_packet(len(pdata), tcp_data)


def replay_iterator(pcap, redis_port=6379, src_ip=None, dst_ip=None):
    from scapy.all import PcapReader
    import itertools
    reader = PcapReader(pcap)

    def packet_filter(p):
        return (p.payload.sport == redis_port or p.payload.dport == redis_port) and \
             (src_ip == None or src_ip == p.payload.src) and \
             (dst_ip == None or dst_ip == p.payload.dst)

    def map_to_pcap(packet):
        return packet.time, packet.original

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


class RedisSession():
    def __init__(self):
        self.req_reader = hiredis.Reader()
        self.req_reader.setmaxbuf(0)
        self.resp_reader = hiredis.Reader()
        self.resp_reader.setmaxbuf(0)

        self.commands = []
        self.responses = 0
        self.request_size = 0
        self.response_size = 0

    def is_receiving(self):
        return self.response_size > 0

    def is_complete(self):
        return self.responses > 0 and self.responses == len(self.commands)

    def process_request_packet(self, length, data):
        self.request_size += length
        self.req_reader.feed(data)

        try:
            command = self.req_reader.gets()
            # command will be False or an array of tokens that describe the command
            while command is not False:
                self.commands.append(' '.join(command))
                command = self.req_reader.gets()
        except hiredis.ProtocolError:
            logging.debug('Partial command')

    def process_response_packet(self, length, data):
        self.response_size += length
        self.resp_reader.feed(data)

        try:
            response = self.resp_reader.gets()
            while response is not False:
                self.responses += 1
                response = self.resp_reader.gets()
        except hiredis.ProtocolError:
            logging.debug('Partial response')

    def clear(self):
        self.commands = []
        self.responses = 0
        self.request_size = 0
        self.response_size = 0

