from setuptools import find_packages, setup

setup(
    name="netsentry",
    version="1.0.0",
    description="PCAP dosyalarindan C2 beacon, DNS tuneli ve veri sizintisi tespiti",
    packages=find_packages(exclude=["tests", "tools"]),
    python_requires=">=3.8",
    entry_points={"console_scripts": ["netsentry=netsentry.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
