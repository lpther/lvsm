# from distutils.core import setup
from setuptools import setup
import lvsm

setup(
    name='lvsm',
    version=lvsm.__version__,
    author=lvsm.__author__,
    author_email='khosrow@khosrow.ca',
    packages=['lvsm', 'lvsm.test'],
    url='https://github.com/khosrow/lvsm',
    license='LICENSE.rst',
    description=lvsm.__doc__.strip(),
    long_description=open('README.rst').read(),
    entry_points={
        'console_scripts': [
            'lvsm = lvsm.__main__:main',
        ],
    },
)