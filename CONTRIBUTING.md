# Contributing to DDoS Defense Platform

Thank you for your interest in contributing to the DDoS Defense Platform! This document provides guidelines and instructions for contributing to the project.

## Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/ddos-defense-platform.git
   cd ddos-defense-platform
Set up development environment:

bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install -e .
Run tests to ensure everything works:

bash
make test
Development Workflow
Branch Naming
Use descriptive branch names: feature/feature-name, bugfix/issue-number, docs/update-readme.

Keep branches focused on a single change.

Code Style
Follow PEP 8 for Python code.

Use black for formatting:

bash
make format
Use flake8 and pylint for linting:

bash
make lint
Commit Messages
Write clear, concise commit messages.

Use the imperative tense (e.g., "Add feature" not "Added feature").

Reference issues when applicable.

Testing
Write unit tests for new functionality in tests/unit/.

Write integration tests for cross-component changes in tests/integration/.

Run all tests before submitting a pull request:

bash
make test
Aim for high test coverage; new code should include appropriate tests.

Documentation
Update docstrings for any new functions or classes.

Update relevant documentation in docs/ if adding or changing features.

Add examples if applicable.

Submitting Changes
Push to your fork and create a pull request against the main branch.

Describe your changes in the pull request description.

Link any related issues (e.g., "Fixes #123").

Ensure all checks pass (CI will run tests and linters).

Request a review from maintainers.

Code of Conduct
We are committed to providing a welcoming and inclusive environment for all contributors. Please be respectful and considerate in all interactions.

Reporting Issues
Use the GitHub issue tracker to report bugs or request features.

Provide as much detail as possible:

Steps to reproduce

Expected behavior

Actual behavior

Environment (OS, Python version, etc.)

Development Tips
Running Individual Services
Ingestion: make run-ingestion

Detection: make run-detection

Mitigation: make run-mitigation

API: make run-api

Using Docker Compose
For a full stack environment (Kafka, PostgreSQL, Redis, services):

bash
make docker-up
Debugging
Set LOG_LEVEL=DEBUG in .env for verbose logging.

Use pdb or ipdb for interactive debugging.

License
By contributing, you agree that your contributions will be licensed under the MIT License.