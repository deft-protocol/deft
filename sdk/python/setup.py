from setuptools import setup, find_packages

setup(
    name="deft-client",
    version="2.3.3",
    description="DEFT Protocol Python SDK - Delta-Enabled File Transfer Client",
    author="DEFT Protocol",
    author_email="contact@deft-protocol.io",
    url="https://github.com/deft-protocol/deft",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
