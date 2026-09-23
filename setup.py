"""Package definition for NIDS."""

from setuptools import find_packages, setup

with open("requirements.txt", "r") as f:
    requirements = [
        line.strip() for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="nids",
    version="1.0.0",
    description="Production-grade Network Intrusion Detection System with from-scratch ML",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="NIDS Project",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(include=["src", "src.*"]),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "nids-train=scripts.train_pipeline:main",
            "nids-serve=scripts.run_server:main",
            "nids-predict=scripts.predict:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
)
