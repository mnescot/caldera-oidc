from setuptools import setup, find_packages

setup(
    name='caldera-oidc-plugin',
    version='1.0.0',
    description='An OIDC authentication plugin for MITRE Caldera',
    author='Your Name',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'aiohttp>=3.8.1',
        'PyJWT>=2.3.0'
    ]
)
