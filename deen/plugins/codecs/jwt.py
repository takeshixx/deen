from __future__ import absolute_import
import sys
import json
try:
    import jwt
    import jwt.algorithms
    PYJWT = True
except ImportError:
    PYJWT = False

from .. import DeenPlugin
from deen.exceptions import MissingDependencyException


class DeenPluginJwt(DeenPlugin):
    name = 'jwt'
    display_name = 'JWT'
    cmd_name = 'jwt'
    cmd_help='Encode/Decode JSON Web Tokens (RFC 7519)'

    def __init__(self):
        super(DeenPluginJwt, self).__init__()

    @staticmethod
    def prerequisites():
        try:
            import jwt
        except ImportError:
            return False
        else:
            return True

    def process(self, data, secret='', algo='HS256'):
        super(DeenPluginJwt, self).process(data)
        if not PYJWT:
            self.error = MissingDependencyException('pyjwt module missing')
            return data
        try:
            json.loads(data)
        except Exception as e:
            self.error = e
            return data
        try:
            data = jwt.encode(data, secret, algorithm=algo)
            data = json.dumps(data)
            data = data.encode()
        except Exception as e:
            print(e)
            self.error = e
        return data

    def unprocess(self, data, secret='', verify=False):
        super(DeenPluginJwt, self).unprocess(data)
        if not PYJWT:
            self.error = MissingDependencyException('pyjwt module missing')
            return data
        try:
            data = jwt.decode(bytes(data), secret, verify=verify)
            data = json.dumps(data)
            data = data.encode()
        except Exception as e:
            self.error = e
        return data

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None):
        if not cmd_aliases:
            cmd_aliases = []
        # Python 2 argparse does not support aliases
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(cmd_name, help=cmd_help)
        else:
            parser = argparser.add_parser(cmd_name, help=cmd_help, aliases=cmd_aliases)
        parser.add_argument('plugindata', action='store',
                            help='input data', nargs='?')
        parser.add_argument('-r', '--revert', action='store_true', dest='revert',
                            default=False, help='revert plugin process')
        parser.add_argument('-f', '--file', dest='plugininfile', default=None,
                            help='file name or - for STDIN', metavar='filename')
        parser.add_argument('-s', '--secret', dest='pluginsecret', default=None,
                            help='JWT secret', metavar='secret')
        parser.add_argument('-m', '--mac', dest='pluginmac', help='JWT MAC algorithm',
                            default='HS256',choices=jwt.algorithms.get_default_algorithms().keys())
        parser.add_argument('-v', '--verify', dest='pluginverify', default=False,
                            help='force signature and claims verification',
                            action='store_true')

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
        if not args.revert:
            return self.process(self.content, secret=args.pluginsecret,
                                algo=args.pluginmac)
        else:
            return self.unprocess(self.content, secret=args.pluginsecret,
                                  verify=args.pluginverify)
