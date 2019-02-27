import time
import datetime

from .. import DeenPlugin


class DeenPluginUnixTimestamp(DeenPlugin):
    name = 'unix_timestamp'
    display_name = 'UNIX Timestamp'
    cmd_name = 'unix-timestamp'
    cmd_help='Convert UNIX timestamps'

    def __init__(self):
        super(DeenPluginUnixTimestamp, self).__init__()

    def process(self, data):
        super(DeenPluginUnixTimestamp, self).process(data)
        # Try to Convert ctime string to Unix Timestamp
        try:
            data = str(int(time.mktime(datetime.datetime.strptime(
                ''.join(map(chr, data.strip())), '%Y-%m-%d %H:%M:%S').timetuple())))
            data = data.encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginUnixTimestamp, self).unprocess(data)
        try:
            data = datetime.datetime.fromtimestamp(int(data)).strftime('%Y-%m-%d %H:%M:%S')
            data = data.encode()
        except (UnboundLocalError, ValueError) as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
