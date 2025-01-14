from setuptools import setup, find_packages

setup(
    name="azhound_scenttrail",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'neo4j',
        'requests',
        'pytest',
        # Add other dependencies as needed
    ],
    author="Andrew Chang",
    author_email="andrew.chang@praetorian.com",
    description="A tool to extend Azurehound for analyzing Azure RBAC role assignments",
    keywords="azure, security, roles",
    url="http://github.com/yourusername/azhound_scenttrail",
    project_urls={
        "Bug Tracker": "http://github.com/timeforchang/azhound_scenttrail/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)