from setuptools import setup, find_packages

setup(
    name="securecrypto",
    version="1.0.0",
    description="CryptoToolkit — AES-256-GCM, RSA-PSS, Argon2id",
    author="Nguyen Phuc Thinh",
    author_email="pthink@student.university.edu.vn",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "cryptography>=42.0.0",
        "pycryptodome>=3.20.0",
        "argon2-cffi>=23.1.0",
        "Flask>=3.0.0",
        "Pillow>=10.0.0",
    ],
    entry_points={
        "console_scripts": [
            "securecrypto=securecrypto.cli:main",
        ],
    },
)
