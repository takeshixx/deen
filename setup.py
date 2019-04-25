from setuptools import setup
import deen.constants

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(name='deen',
      version=deen.constants.__version__,
      install_requires=[
            'PyQt5',
            'jsbeautifier',
            'dicttoxml',
            'xmltodict',
            'bcrypt',
            'python-jose',
            'pyOpenSSL',
            'jsbeautifier'],
      extras_require={'Assembling': 'keystone-engine',
                      'Disassembling': 'capstone'},
      packages=['deen',
                'deen.gui',
                'deen.gui.widgets',
                'deen.plugins',
                'deen.plugins.codecs',
                'deen.plugins.compressions',
                'deen.plugins.assemblies',
                'deen.plugins.hashs',
                'deen.plugins.formatters',
                'deen.plugins.misc'],
      entry_points={
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
      description='Generic data DEcoding/ENcoding application built with PyQt5',
      long_description=long_description,
      long_description_content_type='text/markdown',
      classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
      ])
