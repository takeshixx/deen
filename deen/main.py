import sys
import logging
import os.path
import argparse

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon

from deen.widgets.core import Deen
from deen.transformers.core import DeenTransformer, X509Certificate
from deen.transformers.formats import XmlFormat, HtmlFormat, JsonFormat
from deen.core import *

ICON = os.path.dirname(os.path.abspath(__file__)) + '/media/icon.png'
LOGGER = logging.getLogger()
logging.basicConfig(format='[%(pathname)s - %(funcName)s() - %(lineno)s] %(message)s')

ARGS = argparse.ArgumentParser(description='apply encodings, compression and hashing to arbitrary input data.')
ARGS.add_argument('infile', nargs='?', default=None,
                  help="file name or - for STDIN")
ARGS.add_argument('-l', '--list', action='store_true', dest='list',
                  default=False, help='list supported ENCODINGS/COMPRESSIONS/HASHS')
ARGS.add_argument('-d', '--decode', action='store', dest='decode',
                  metavar='ENCODING', default=None, help='decode data with ENCODING')
ARGS.add_argument('-e', '--encode', action='store', dest='encode',
                  metavar='ENCODING', default=None, help='encode data with ENCODING')
ARGS.add_argument('-u', '--uncompress', action='store', dest='uncompress',
                  metavar='COMPRESSION', default=None, help='uncompress data witn COMPRESSION')
ARGS.add_argument('-c', '--compress', action='store', dest='compress',
                  metavar='COMPRESSION', default=None, help='compress data with COMPRESSION')
ARGS.add_argument('-f', '--format', action='store', dest='format',
                  metavar='FORMATTER', default=None, help='format data with FORMATTER')
ARGS.add_argument('--hash', action='store', dest='hash',
                  default=None, help='hash data with hash algorithm')
ARGS.add_argument('--x509', action='store_true', dest='x509_certificate',
                  default=False, help='print X509 certificate in human readable format')
ARGS.add_argument('--data', action='store', dest='data',
                  default=None, help='instead of a file, provide an input string')
ARGS.add_argument('-n', action='store_true', dest='nonewline',
                  default=False, help='omit new line character at the end of the output')


def list_supported_transformers():
    print('Encodings:')
    for e in ENCODINGS:
        print('\t' + e)
    print()
    print('Compressions:')
    for c in COMPRESSIONS:
        print('\t' + c)
    print()
    print('Hashs:')
    for h in HASHS:
        print('\t' + h)
    try:
        import OpenSSL.crypto
    except ImportError:
        MISC.remove('X509Certificate')
    if MISC:
        print()
        print('Misc')
        for m in MISC:
            print('\t' + m)
    print()
    print('Formatters:')
    for f in FORMATTERS:
        print('\t' + f)


def main():
    args = ARGS.parse_args()
    content = None
    if args.infile:
        try:
            if args.infile == '-':
                try:
                    stdin = sys.stdin.buffer
                except AttributeError:
                    stdin = sys.stdin
                content = stdin.read()
            else:
                with open(args.infile, 'rb') as f:
                    content = f.read()
        except KeyboardInterrupt:
            return
    elif args.data:
        content = bytearray(args.data, 'utf8')
    if any([args.encode, args.decode, args.uncompress,
            args.compress, args.hash, args.list,
            args.x509_certificate, args.format]):
        # We are in command line mode
        if args.list:
            list_supported_transformers()
            return
        if not content:
            LOGGER.error('Please provide a file or pipe into STDIN')
            sys.exit(1)
        transformer = DeenTransformer()
        try:
            # Python 3
            stdout = sys.stdout.buffer
        except AttributeError:
            # Python 2
            stdout = sys.stdout
        if args.decode:
            decoded = transformer.decode(args.decode, content)
            assert isinstance(decoded, tuple)
            stdout.write(decoded[0])
        elif args.encode:
            encoded = transformer.encode(args.encode, content)
            stdout.write(encoded)
        elif args.compress:
            compressed = transformer.compress(args.compress, content)
            stdout.write(compressed)
        elif args.uncompress:
            uncompressed = transformer.uncompress(args.uncompress, content)
            assert isinstance(uncompressed, tuple)
            stdout.write(uncompressed[0])
        elif args.hash:
            hashed = transformer.hash(args.hash, content)
            stdout.write(hashed)
        elif args.format:
            if args.format in FORMATTERS:
                formatter = None
                if args.format == 'XML':
                    formatter = XmlFormat()
                elif args.format == 'HTML':
                    formatter = HtmlFormat()
                elif args.format == 'JSON':
                    formatter = JsonFormat()
                if formatter:
                    formatter.content = content
                    if formatter.content:
                        stdout.write(formatter.content)
        elif args.x509_certificate:
            certificate = X509Certificate()
            certificate.certificate = content
            stdout.write(certificate.decode())
        if not args.nonewline:
            stdout.write(b'\n')
    else:
        # We are in GUI mode
        app = QApplication(sys.argv)
        ex = Deen()
        if content:
            # GUI mode also supports input files and
            # content via STDIN.
            ex.encoder_widget.set_root_content(content)
        ex.setWindowIcon(QIcon(ICON))
        LOGGER.addHandler(ex.log)
        return app.exec_()
