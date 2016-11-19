from setuptools import setup

setup(name='DEEN',
      version='0.4.0',
      install_requires=['PyQt5'],
      packages=['deen',
                'deen.widgets'],
      entry_points = {
            'console_scripts': ['deen=deen.main:main']},
      url='https://github.com/takeshixx/deen',
      license='Apache 2.0',
      author='takeshix',
      description='Generic decoding/encoding application')
