from setuptools import setup

setup(name='deen',
      version='0.6.1',
      install_requires=['PyQt5'],
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
