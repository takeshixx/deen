from setuptools import setup
import deen.core

setup(name='deen',
      version=deen.core.__version__,
      install_requires=['PyQt5',
                        'lxml'],
      extras_require={'X509': 'pyOpenSSL'},
      packages=['deen',
                'deen.widgets',
                'deen.transformers'],
      entry_points = {
            'console_scripts': ['deen=deen.main:main']},
      url='https://github.com/takeshixx/deen',
      package_data={
          'deen': ['icon.png']},
      license='Apache 2.0',
      author='takeshix',
      description='Generic decoding/encoding application')
