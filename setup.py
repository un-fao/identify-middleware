#    Copyright 2025 FAO
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
#    Author: Carlo Cancellieri (ccancellieri@gmail.com)
#    Company: FAO, Viale delle Terme di Caracalla, 00100 Rome, Italy
#    Contact: copyright@fao.org - http://fao.org/contact-us/terms/en/

# setup.py

from setuptools import setup, find_packages

setup(
    name="identify_middleware",
    version="0.2.0", # Bumped version for new features
    description="Identify Middleware for GCP Applications",
    author="Carlo Cancellieri",
    author_email="ccancellieri@gmail.com",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    # Core dependencies that are always required
    install_requires=[
        "httpx>=0.27.0",
        "python-jose[cryptography]>=3.3.0", # For local JWT validation
        "pydantic>=2.0",
    ],
    # Optional dependencies, installable with e.g., `pip install .[google,fastapi]`
    extras_require={
        "google": ["google-auth>=2.20.0"],
        "fastapi": ["fastapi>=0.110.0", "starlette-session>=0.2.0"],
        "flask": ["flask>=3.0.0", "Flask-Session>=0.6.0"],
        "redis": ["redis>=5.0.0"],
        "all": [
            "google-auth>=2.20.0",
            "fastapi>=0.110.0", "starlette-session>=0.2.0",
            "flask>=3.0.0", "Flask-Session>=0.6.0",
            "redis>=5.0.0",
        ],
        "testing": ["pytest>=8.0.0", "pytest-asyncio>=0.23.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)