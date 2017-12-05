import sys

__version__ = '0.9.9'
__all__ = ['ENCODINGS',
           'COMPRESSIONS',
           'HASHS',
           'MISC',
           'FORMATTERS']

ENCODINGS = ['Base64',
             'Base64 URL',
             'Base32',
             'Hex',
             'URL',
             'HTML',
             'Rot13',
             'UTF8',
             'UTF16']

COMPRESSIONS = ['Gzip',
                'Bz2']

HASHS = ['MD5',
         'SHA1',
         'SHA224',
         'SHA256',
         'SHA384',
         'SHA512',
         'RIPEMD160',
         'MD4',
         'MDC2',
         'NTLM',
         'Whirlpool',
         'MySQL']

MISC = []

try:
    import OpenSSL.crypto
except ImportError:
    pass
else:
    MISC.append('X509Certificate')

FORMATTERS = ['XML',
              'HTML',
              'JSON']

# Add features based on Python version
if sys.version_info.major == 3:
    if sys.version_info.minor >= 6:
        HASHS.append('BLAKE2b')
        HASHS.append('BLAKE2s')
    if sys.version_info.minor >= 4:
        ENCODINGS.insert(3, 'Base85')
