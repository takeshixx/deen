# deen

A GUI application that allows to encode, compress, hash, ... generic input data. It is meant to be a handy tool for quick encoding/decoding tasks for data to be used in other applications. It aims to be a lightweight alternative to other tools that might take a long time to startup and should not have too many dependencies.

## Compatibility

The code should be compatible with Python 2 (at least 2.7.x) and Python 3. However, deen is mainly developed for Python 3 and some features may be temporarily broken in Python 2. It is strongly recommended to use deen with Python 3.

## Installation

```bash
python setup.py install
```

## GUI

By invoking deen without any command line arguments, the graphical interface will start.

![deen](https://kleber.io/NGp/)

The GUI also supports reading input from files:

```
deen /bin/ls
```

and from STDIN:

```
cat /bin/ls | deen -
```

## CLI

Some functionality is also available via a CLI. A list of available operations and supported transfomers is available in the help page (`-h`/`--help`) and with the list command (`-l`/`--list`). The command line can read input either from a file:

```
deen --hash sha256 /bin/ls
```

or from STDIN by using `-` as a file name:

```
cat /bin/ls | deen --hash sha256 -
```

Alternatively an input string can also be supplied with the `--data` argument:

```
deen --encode base64 --data admin:admin
```