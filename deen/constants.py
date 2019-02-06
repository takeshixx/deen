__version__ = '1.7.1'

about_text = ('deen (DEcoderENcoder) v%s\n\nA decoding/encoding application for arbitrary data.\n\n'
              'https://github.com/takeshixx/deen') % __version__

icon_path = '/media/icon.png'

verbose_log_format = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s'

cli_description = 'Apply encodings, compression, hashing and other types of transformations to arbitrary input data.'

cli_epilog = """examples:
  open a file in the deen GUI:
    $ deen /bin/ls

  open file from STDIN in deen GUI:
    $ cat /bin/ls | deen -

  base64 encode a string:
    $ deen -b base64 -d admin:admin
    YWRtaW46YWRtaW4=

  base64 encode a string with subcommand:
    $ deen base64 admin:admin
    YWRtaW46YWRtaW4=

  decode Base64 string:
    $ deen -b base64 -r -d YWRtaW46YWRtaW4=
    admin:admin

  decode Base64 string with subcommand:
    $ deen base64 -r YWRtaW46YWRtaW4=
    admin:admin

  calculate the SHA256 hash of file:
    $ deen sha256 /bin/ls
    df285ab34ad10d8b641e65f39fa11a7d5b44571a37f94314debbfe7233021755
"""