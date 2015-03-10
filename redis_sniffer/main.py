import argparse
import logging
from sniffer import Sniffer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help="the interface to bind to")
    parser.add_argument('-p', '--port', type=int, help="the port to grab packets from.  Default: 6379", default=6379)
    parser.add_argument('--out', help="the location to generate the full or event logs, defaults to the directory the \
                        application is executed from")
    parser.add_argument('-l', choices=['both', 'event', 'full'], default='both', help="the type of log(s) you want to \
                        create. Default: both")
    parser.add_argument('-el', '--event-log', default="event_sniff", help="the name of the event outout file. \
                        Default: event_sniff")
    parser.add_argument('-fl', '--full-log', default="full_sniff", help="the name of the full sniff output file. \
                        Default: full_sniff")
    parser.add_argument('-f', '--filter', default="none", help="comma separated list of events to log(ex: setex,delete)"
                        )
    args = parser.parse_args()
    fmt_full = '%.6f %-21s %8d %8d %s\n'
    fmt = '%s\n'
    path = ""

    event_filters = args.filter.split(',')
    if args.out:
        path = args.out

    if args.l == 'both':
        full_output = open(path + args.full_log, 'w')
        event_output = open(path + args.event_log, 'w')
    elif args.l == 'full':
        full_output = open(path + args.full_log, 'w')
    elif args.l == 'event':
        event_output = open(path + args.event_log, 'w')
    for session in Sniffer.sniff(args.interface, args.port):
        ptime, client, req_size, resp_size, command = session
        comm_parts = command.split()
        if comm_parts[0].lower() not in event_filters:
            continue
        if args.l == 'event':
            event_output.write(fmt % command)
            event_output.flush()
        elif args.l == 'full':
            full_output.write(fmt_full % (ptime, client, req_size, resp_size, command))
            full_output.flush()
        else:
            event_output.write(fmt % command)
            full_output.write(fmt_full % (ptime, client, req_size, resp_size, command))
            event_output.flush()
            full_output.flush()

if __name__ == '__main__':
    main()