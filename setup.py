"""Setup configuration for DDoS Defense Platform."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="ddos-defense-platform",
    version="0.1.0",
    author="DDoS Defense Platform Contributors",
    description="Real-time DDoS attack detection and mitigation for cloud networks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/ddos-defense-platform",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ddos-ingestion=ingestion.main:main",
            "ddos-detection=detection.main:main",
            "ddos-mitigation=mitigation.main:main",
            "ddos-api=api.app:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)