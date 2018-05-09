from setuptools import setup
import deen.constants

setup(name='deen',
      version=deen.constants.__version__,
      extras_require={'X509': 'pyOpenSSL',
                      'JS-Beautifier': 'jsbeautifier'},
      packages=['deen',
                'deen.widgets',
                'deen.transformers'],
      entry_points = {
            'console_scripts': ['deen=deen.main:main']},
      url='https://github.com/takeshixx/deen',
      package_data={
          'deen': ['media/icon.png',
                   'media/edit-clear.svg',
                   'media/edit-copy.svg',
                   'media/go-up.svg',
                   'media/document-save-as.svg',
                   'media/dark/edit-clear.svg',
                   'media/dark/edit-copy.svg',
                   'media/dark/go-up.svg',
                   'media/dark/document-save-as.svg']},
      license='Apache 2.0',
      author='takeshix',
      description='Generic decoding/encoding application')
