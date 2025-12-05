"""
Setup configuration for LeakTorch
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / 'README.md'
long_description = readme_file.read_text(encoding='utf-8') if readme_file.exists() else ''

setup(
    name='leaktorch',
    version='1.0.0',
    author='LeakTorch Contributors',
    author_email='contact@leaktorch.dev',
    description='Git Repository Secret Scanner - Detect accidentally committed secrets',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/leaktorch/leaktorch',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    keywords='security git secrets scanner leak detection credentials',
    python_requires='>=3.7',
    install_requires=[
        'gitpython>=3.1.0',
        'colorama>=0.4.4',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=3.0.0',
            'black>=22.0.0',
            'flake8>=4.0.0',
            'mypy>=0.950',
        ],
    },
    entry_points={
        'console_scripts': [
            'leaktorch=leaktorch.cli:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/leaktorch/leaktorch/issues',
        'Source': 'https://github.com/leaktorch/leaktorch',
        'Documentation': 'https://github.com/leaktorch/leaktorch/wiki',
    },
    include_package_data=True,
    zip_safe=False,
)
