import sys
import logging
import os.path
import argparse

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon

from deen.widgets.core import Deen
from deen.core import ENCODINGS, COMPRESSIONS, HASHS

ICON = os.path.dirname(os.path.abspath(__file__)) + '/icon.png'
LOGGER = logging.getLogger()
logging.basicConfig(format='[%(lineno)s - %(funcName)s() ] %(message)s')

ARGS = argparse.ArgumentParser()
ARGS.add_argument('infile', nargs='?', default=None,
                  help="File name or - for STDIN")
ARGS.add_argument('--data', action='store', dest='data',
                  default=None, help='Input data')
ARGS.add_argument('--decode', action='store', dest='decode',
                  default=None, help='Decode data')
ARGS.add_argument('--encode', action='store', dest='encode',
                  default=None, help='Encode data')
ARGS.add_argument('--uncompress', action='store', dest='uncompress',
                  default=None, help='Uncompress data')
ARGS.add_argument('--compress', action='store', dest='compress',
                  default=None, help='Compress data')
ARGS.add_argument('--hash', action='store', dest='hash',
                  default=None, help='Hash data')


def main():
    args = ARGS.parse_args()
    content = None
    if args.infile:
        if args.infile == '-':
            try:
                stdin = sys.stdin.buffer
            except AttributeError:
                stdin = sys.stdin
            content = stdin.read()
        else:
            with open(args.infile, 'rb') as f:
                content = f.read()
    elif args.data:
        content = args.data
    if any([args.encode, args.decode, args.uncompress,
            args.compress, args.hash, args.list]):
        # We are in command line mode
        if args.list:
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
            return
        if not content:
            LOGGER.error('Please provide a file or pipe into STDIN')
            sys.exit(1)
        from deen.transformers.core import DeenTransformer
        transformer = DeenTransformer()
        if args.decode:
            decoded = transformer.decode(args.decode, content)
            print(decoded)
        elif args.encode:
            encoded = transformer.encode(args.encode, content)
            print(encoded)
        elif args.compress:
            compressed = transformer.compress(args.compress, content)
            print(compressed)
        elif args.uncompress:
            uncompressed = transformer.uncompress(args.uncompress, content)
            print(uncompressed)
        elif args.hash:
            hashed = transformer.hash(args.hash, content)
            print(hashed)
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
