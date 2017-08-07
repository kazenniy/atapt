from distutils.core import setup
setup(
    name = 'atapt',
    packages = ['atapt'],
    version = '0.4',
    description = 'ATA Pass-Through library',
    author = 'Seregy Kazenniy',
    author_email = 'kazenniy@gmail.com',
    url = 'https://github.com/kazenniy/atapt',
    download_url = 'https://github.com/kazenniy/atapt/tarball/master',
    keywords = ['ata', 'sgio', 'hdd', 'ssd', 'smart'],
    license='MIT',
    classifiers = [
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
	'Programming Language :: Python :: 3.0',
	'Programming Language :: Python :: 3.1',
	'Programming Language :: Python :: 3.2',
	'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
)
