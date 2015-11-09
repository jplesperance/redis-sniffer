import argparse
from sniffer import Sniffer
from log import Log
import logging
import os


def main():
    parser = argparse.ArgumentParser()
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('-i', '--interface', help="the interface to bind to")
    source_group.add_argument('-F', '--file', help="pcap file containing captured traffic to analyze")
    parser.add_argument('-p', '--port', type=int, help="the port to grab packets from.  Default: 6379", default=6379)
    parser.add_argument('--out', default='.', help="the location to generate the full or event logs, defaults to the \
                        directory the application is executed from")
    parser.add_argument('-l', choices=['debug', 'event', 'full'], default='full', help="the type of log(s) you want to \
                        create. Default: full")
    parser.add_argument('-el', '--event-log', default="event", help="the name of the event outout file. \
                        Default: event_sniff")
    parser.add_argument('-fl', '--full-log', default="full", help="the name of the full sniff output file. \
                        Default: full_sniff")
    parser.add_argument('-f', '--filter', default="", help="comma separated list of events to log(ex: setex,delete)"
                        )
    parser.add_argument('--append', default="_sniff", help="the suffix to append to command logs")
    parser.add_argument('--extra', help="log non-redis traffic")
    args = parser.parse_args()
    fmt_full = '%.6f %-21s %8d %8d %s\n'
    fmt = '%s\n'
    event_filters = args.filter.split(',') if args.filter else []

    logger = Log(args.l, args.out, {'event': args.event_log, 'full': args.full_log}, event_filters, args.append)

    log_level = logging.INFO
    if args.l == 'debug':
        log_level = logging.DEBUG

    logging.basicConfig(filename=os.path.join(args.out, 'sniffer.log'), level=log_level)

    source = args.interface if args.interface else args.file
    sniffer = Sniffer(source, args.port)

    for session in sniffer.sniff():
        ptime, client, req_size, resp_size, command = session
        comm_parts = command.split()
        if comm_parts[0].lower() in event_filters:
            logger.write_command(comm_parts[0].lower(), command)
        if logger.event_log:
            logger.write_event(fmt % command)
        if logger.full_log:
            logger.write_log(fmt_full % (ptime, client, req_size, resp_size, command))

if __name__ == '__main__':
    main()
