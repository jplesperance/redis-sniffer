import io
import os
import sys

class Log:

    def __init__(self, log_level="full", location='', files_names={}, filters=[], append="_sniff"):
        if log_level == "event" or log_level == "full" or log_level == "debug":
            path = os.path.join(location, files_names['event'] + append)
            try:
                self.event_log = io.open(path, 'w')
            except IOError:
                sys.exit('Unable to write to file: {}'.format(path))
        if log_level == "full" or  log_level == "debug":
            path = os.path.join(location, files_names['full'] + append)
            try:
                self.full_log = io.open(path, 'w')
            except IOError:
                sys.exit('Unable to write to file: {}'.format(path))
        self.files = {}
        if log_level == 'extra':
            try:
                self.extra_log = io.open(location + "redis_extra.out", 'w')
            except IOError:
                sys.exit('Unable to write to file: ' + location + "redis_extra.out")

        for event in filters:
            self.files[event] = io.open(location + event + append, 'w')

    def write_event(self, event):
        self.event_log.write(unicode(event))
        self.event_log.flush()

    def write_log(self, log):
        self.full_log.write(unicode(log))
        self.full_log.flush()

    def write_debug(self, data):
        self.debug_log.write(unicode(data))
        self.debug_log.flush()

    def write_command(self, event, command):
        if event in self.files.keys():
            self.files[event].write(unicode(command))
            self.files[event].flush()

    def write_extra(self, data):
        self.extra_log.write(unicode(data))
        self.extra_log.flush()
