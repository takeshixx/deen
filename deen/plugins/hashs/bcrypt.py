import sys
try:
    import bcrypt
    BCRYPT = True
except ImportError:
    BCRYPT = False

from .. import DeenPlugin

__all__ = ['DeenPluginBcrypt']


class DeenPluginBcrypt(DeenPlugin):
    name = 'bcrypt'
    display_name = 'bcrypt'
    cmd_name = 'bcrypt'
    cmd_help = 'Hash passwords with bcrypt'

    def __init__(self):
        super(DeenPluginBcrypt, self).__init__()

    def prerequisites(self):
        try:
            import bcrypt
            return True
        except ImportError:
            self.log_missing_depdendencies('bcrypt')
            return False

    def process(self, data, salt=None, password=None, check=False):
        super(DeenPluginBcrypt, self).process(data)
        if not BCRYPT:
            return
        if not salt:
            salt = bcrypt.gensalt()
        if salt and not isinstance(salt, bytes):
            salt = salt.encode()
        if password and not isinstance(password, bytes):
            password = password.encode()
        if check and password:
            try:
                state = bcrypt.checkpw(password, bytes(data))
                if state:
                    data = b'Hash is valid for given password'
                else:
                    data = b'Invalid hash for given password'
            except Exception as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return b'Invalud input data: ' + str(e).encode()
        else:
            try:
                data = bcrypt.hashpw(bytes(data), salt)
            except ValueError as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
                return b'Invalid salt: ' + salt
        return data

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None,
                      *args, **kwargs):
        if not cmd_aliases:
            cmd_aliases = []
        # Python 2 argparse does not support aliases
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(cmd_name, help=cmd_help)
        else:
            parser = argparser.add_parser(cmd_name, help=cmd_help, aliases=cmd_aliases)
        parser.add_argument('plugindata', action='store', help='input data', nargs='?')
        parser.add_argument('-f', '--file', dest='plugininfile', default=None,
                            help='file name or - for STDIN', metavar='filename')
        parser.add_argument('-s', '--salt', dest='pluginsalt', default=None,
                            help='Hashing salt', metavar='salt')
        parser.add_argument('-c', '--check', dest='plugincheck', default=False,
                            help='check the bcrypt hash of a given password',
                            action='store_true')
        parser.add_argument('-p', '--password', dest='pluginpassword', default=None,
                            help='Password for checking a bcrypt hash', metavar='salt')

    def process_cli(self, args):
        if not self.content:
            if not args.plugindata:
                if not args.plugininfile:
                    self.content = self.read_content_from_file('-')
                else:
                    self.content = self.read_content_from_file(args.plugininfile)
            else:
                self.content = args.plugindata
        if not self.content:
            return
        return self.process(self.content, salt=args.pluginsalt, password=args.pluginpassword,
                            check=args.plugincheck)
