# PeoChain Validator Bond Marketplace

## Overview
PeoChain is a truly permissionless platform for secure validator bonding featuring advanced cryptography, non-custodial escrow, and fully deterministic mechanisms with no administrative control points.

## Core Principles

- **Truly Non-custodial:** Validators maintain complete control of their assets through cryptographic proof only
- **Permissionless Participation:** Anyone can become a validator through cryptographic verification without administrative approval
- **Deterministic Assignment:** Subnet assignment is fully deterministic with no subjective elements or administrative override
- **Objective Performance:** Performance is measured through cryptographically verifiable consensus participation only

## Architecture

The PeoChain Validator Bond Marketplace is built on three core components:

1. **Native Runtime Module:** A Substrate-based runtime module that implements permissionless validator registration, deterministic subnet assignment, and objective performance tracking.

2. **CLI-First Approach:** A command-line interface that allows validators to interact directly with the chain without administrative intermediaries.

3. **Threshold Signatures:** Enhanced security through distributed cryptographic signing with no single point of failure.

## Getting Started

### Prerequisites
- Rust 1.65 or later
- Substrate development environment

### Installation

```bash
# Clone the repository
git clone https://github.com/peochain/validator-bond-marketplace.git

# Build the runtime module
cd peochain-validator-bond/src/runtime/modules/validator_bond
cargo build --release

# Build the CLI tool
cd ../../../../cli/validator
cargo build --release
```

### Becoming a Validator

The process is fully permissionless and requires no administrative approval:

```bash
# Generate validator keys
./validator-cli generate-keys --output ~/.peochain/validator

# Create a non-custodial escrow
./validator-cli create-escrow --node ws://127.0.0.1:9944 --amount 5000 --timelock 14400

# Register as a validator
./validator-cli register-validator --node ws://127.0.0.1:9944 --key ~/.peochain/validator/validator.key --escrow 0x...

# Check your subnet assignment
./validator-cli check-assignment --node ws://127.0.0.1:9944 --key ~/.peochain/validator/validator.key
```

### Threshold Signature Support

For enhanced security, you can create a threshold signature escrow:

```bash
# Create a threshold signature escrow (3-of-5)
./validator-cli create-threshold-escrow --node ws://127.0.0.1:9944 --amount 10000 --threshold 3 --participants 5 --timelock 14400
```

## Documentation

Detailed technical documentation is available in the `docs` directory:

- [Runtime Module Architecture](docs/runtime-module.md)
- [CLI Tool Guide](docs/cli-guide.md)
- [Threshold Signatures](docs/threshold-signatures.md)
- [Deterministic Subnet Assignment](docs/subnet-assignment.md)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
