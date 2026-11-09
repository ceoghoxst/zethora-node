# Contributing to Zethora

We are thrilled that you are interested in contributing to Zethora! 

## Code of Conduct
By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and constructive in all communications.

## How to Contribute
1. **Fork the repository** and create your branch from main.
2. **Ensure the test suite passes** (cargo test).
3. **Format your code** (cargo fmt).
4. **Issue a Pull Request** with a clear description of the problem and the solution.

## Contribution Guidelines (Librustzcash Style)
- All new public functions must have doc comments (///).
- Commit messages must be descriptive. Use the imperative mood (e.g., "Add bridge signature check", not "Added bridge signature check").
- Ensure no unhandled unwrap() in production code; use proper error propagation.

## Security Disclosures
If you find a security vulnerability, **DO NOT open a public issue**. Please refer to our SECURITY.md file for responsible disclosure guidelines.

Thank you for helping us build the Apex Predator L1!