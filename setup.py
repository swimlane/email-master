from setuptools import setup


with open('./README.rst') as f:
    long_description = f.read()

setup(
    name='email-master',
    packages=['email_master', 'email_master.eml', 'email_master.msg', 'email_master.pgp'],
    version='0.4.25',
    description='Master Email Parsing Package',
    author='Swimlane',
    author_email="info@swimlane.com",
    long_description=long_description,
    install_requires=[
        "pendulum==2.1.2",
        "compressed-rtf==1.0.5",
        "extract_msg==0.23.2",
        "six==1.13.0",
        "PGPy==0.5.2"
    ],
    keywords=['utilities', 'email', 'parsing', 'eml', 'msg'],
    classifiers=[],
)
