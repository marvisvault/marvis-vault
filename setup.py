from setuptools import setup, find_packages

setup(
    name="marvis-vault",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "typer>=0.9.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vault=vault.cli.main:app",
        ],
    },
    package_data={
        "vault": [
            "templates/*.json",
            "templates/*.yaml",
        ],
    },
    python_requires=">=3.10",
) 