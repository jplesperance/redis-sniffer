import io


class Log:
    def __init__(self, log_level="event", location=None, files_names={}, event_logs=None):
        if log_level == "event" or log_level == "both" or log_level == "debug":
            self.event_log = io.open(location + files_names['event'], 'w')
        elif log_level == "full" or log_level == "both" or log_level == "debug":
            self.full_log = io.open(location + files_names['full'], 'w')
        elif log_level == "debug":
            self.debug_log = io.open(location + files_names['debug'], 'w')

    def write_event(self, event):
        self.event_log.write(event)
        self.event_log.flush()

    def write_log(self, log):
        self.full_log.write(log)
        self.full_log.flush()

    def write_debug(self, data):
        self.debug_log.write(data)
        self.debug_log.flush()