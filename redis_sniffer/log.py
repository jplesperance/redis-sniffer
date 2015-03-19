import io
import sys

class Log:

    def __init__(self, log_level="full", location=None, files_names={}, filters={}, append="_sniff"):
        if log_level == "event" or log_level == "full" or log_level == "debug":
            try:
                self.event_log = io.open(location + files_names['event'], 'w')
            except IOError:
                sys.exit('Unable to write to file: ' + location + files_names['event'])
        if log_level == "full" or  log_level == "debug":
            try:
                self.full_log = io.open(location + files_names['full'], 'w')
            except IOError:
                sys.exit('Unable to write to file: ' + location + files_names['full'])
        if log_level == "debug":
            self.debug_log = io.open('/var/log/rh.out', 'w')
        self.files = {}
        if len(filters) > 0:
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
