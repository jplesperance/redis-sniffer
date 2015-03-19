import argparse
from sniffer import Sniffer
from log import Log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help="the interface to bind to")
    parser.add_argument('-p', '--port', type=int, help="the port to grab packets from.  Default: 6379", default=6379)
    parser.add_argument('--out', help="the location to generate the full or event logs, defaults to the directory the \
                        application is executed from")
    parser.add_argument('-l', choices=['debug', 'event', 'full'], default='full', help="the type of log(s) you want to \
                        create. Default: both")
    parser.add_argument('-el', '--event-log', default="event_sniff", help="the name of the event outout file. \
                        Default: event_sniff")
    parser.add_argument('-fl', '--full-log', default="full_sniff", help="the name of the full sniff output file. \
                        Default: full_sniff")
    parser.add_argument('-f', '--filter', default="none", help="comma separated list of events to log(ex: setex,delete)"
                        )
    parser.add_argument('--append', default="_sniff", help="the suffix to append to command logs")
    args = parser.parse_args()
    fmt_full = '%.6f %-21s %8d %8d %s\n'
    fmt = '%s\n'
    path = ""
    event_filters = args.filter.split(',')
    if args.out:
        path = args.out
    logger = Log(args.l, path, {'event': args.event_log, 'full': args.full_log}, event_filters, args.append)

    for session in Sniffer.sniff(args.interface, args.port):
        ptime, client, req_size, resp_size, command = session
        comm_parts = command.split()
        if comm_parts[0].lower() in event_filters:
            logger.write_command(comm_parts[0].lower(), command)
        if args.l == 'event':
            logger.write_event(fmt % command)
        if args.l == 'full':
            logger.write_log(fmt_full % (ptime, client, req_size, resp_size, command))

if __name__ == '__main__':
    main()