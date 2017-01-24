from setuptools import setup

setup(name='deen',
      version='0.7.1',
      install_requires=['PyQt5'],
      packages=['deen',
                'deen.widgets',
                'deen.transformers'],
      entry_points = {
            'console_scripts': ['deen=deen.main:main']},
      url='https://github.com/takeshixx/deen',
      package_data={
          'deen': ['icon.png']},
      data_files=[
          ('share/applications', ('freedesktop/deen.desktop',))],
      license='Apache 2.0',
      author='takeshix',
      description='Generic decoding/encoding application')
