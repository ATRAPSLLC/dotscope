# Contributing to dotscope

Thank you for your interest in contributing to dotscope! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Documentation](#documentation)
- [Performance Considerations](#performance-considerations)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. We are committed to providing a welcoming and inspiring community for all.

## Getting Started

### Prerequisites

- Rust 1.70.0 or later
- Git
- A code editor with Rust support (VS Code with rust-analyzer recommended)

### Development Setup

1. **Fork and Clone**

   ```bash
   git clone https://github.com/YOUR_USERNAME/dotscope.git
   cd dotscope
   ```

2. **Install Dependencies**

   ```bash
   # Install Rust if you haven't already
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Install additional tools
   cargo install cargo-fuzz cargo-audit cargo-outdated
   rustup component add clippy rustfmt llvm-tools-preview
   ```

3. **Build the Project**

   ```bash
   cargo build
   cargo test-quick
   ```

4. **Set up Pre-commit Hooks** (Optional but recommended)

   ```bash
   # Install pre-commit
   pip install pre-commit
   pre-commit install
   ```

## Contributing Guidelines

### Types of Contributions

We welcome several types of contributions:

- **Bug Fixes**: Fix issues in the codebase
- **Features**: Add new functionality
- **Documentation**: Improve docs, examples, or comments
- **Performance**: Optimize existing code
- **Testing**: Add or improve tests

### Before You Start

1. **Check Existing Issues**: Look for existing issues or discussions about your idea
2. **Create an Issue**: For significant changes, create an issue first to discuss the approach
3. **Start Small**: Consider starting with documentation or small bug fixes to get familiar with the codebase

### Code Style

We follow standard Rust conventions:

```bash
# Format code
cargo fmt

# Check for common issues
cargo clippy --all-features --all-targets -- -D warnings

# Ensure no warnings
RUSTFLAGS="-Dwarnings" cargo build --all-features
```

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add support for parsing PortablePDB extensions
fix: handle malformed metadata table headers gracefully
docs: add examples for disassembly API
test: add fuzzing targets for signature parsing
```

Prefixes:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `ci:` - CI/CD changes

## Pull Request Process

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 2. Make Your Changes

- Write clean, well-documented code
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass locally

### 3. Test Your Changes

**Important**: Do extensive testing locally before pushing:

```bash
# Use the Makefile for comprehensive local testing
make ci          # Run full CI suite locally
make test-quick  # Unit tests and the fast integration tests
make test        # The full test tier: everything, packer suites and corpora included
make test-oracle # The full tier, failing when dotnet, mono, ildasm or peverify is missing
make fuzz        # Run fuzzing (requires nightly Rust)
make coverage    # Generate coverage report
make audit       # Security audit
make check-all   # Full checks (format, clippy, tests, docs)

# Or run individual commands:
cargo test-full
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --all-features --no-deps

# Fuzzing runs only locally, never in CI; for a longer run of one target:
make fuzz FUZZ_TARGETS=cilobject FUZZ_TIME=1800  # 30 minutes
```

### 4. Submit Pull Request

1. Push your branch to your fork
2. Create a pull request with:
   - Clear title and description
   - Reference any related issues
   - Include testing information
   - Mention any breaking changes

### 5. Code Review Process

- Maintainers will review your PR
- Address any requested changes
- Once approved, your PR will be merged

## Testing

### Test Types

Tests run in the `ci-test` profile (release with debug assertions): unoptimised, the
sample-driven tests take hours. The tiers are cargo aliases (`.cargo/config.toml`):

- `cargo test-quick`: the unit tests, the integration tests outside a `full` module and the
  fuzz regression replay.
- `cargo test-full`: everything, including the packer suites, the runtime corpora, the codegen
  validation sweep and lift verification.

1. **Unit Tests**: Test individual functions and modules, in `#[cfg(test)]` modules

2. **Integration Tests**: Test complete workflows, in one binary (`tests/it/main.rs`, one
   module per suite). A slow suite goes under its `full` module.

   ```bash
   cargo test --profile ci-test --features z3 --test it -- ssa::
   ```

3. **Fuzzing**: Test with random inputs, locally (CI replays the committed regressions only).
   A fixed crash's input goes under `dotscope/tests/samples/fuzz-regressions/<target>/`

   ```bash
   make fuzz FUZZ_TARGETS=cilobject
   ```

4. **Benchmarks**: Performance tests

   ```bash
   cargo bench
   ```

### Adding Tests

- Add unit tests in the same file as the code (in `#[cfg(test)]` modules)
- Add integration tests in the `tests/` directory
- Include edge cases and error conditions
- Test with real .NET assemblies when possible

### Test Data

- Use the sample files in `tests/samples/` through `dotscope::testkit::fixture`, and list new
  ones in `tests/samples/MANIFEST.toml` (see `docs/testkit.md`)
- Don't commit large binary files
- Create minimal test cases for specific scenarios

## Documentation

### Code Documentation

- Document all public APIs with `///` comments
- Include examples in doc comments
- Update module-level documentation when adding features

### Examples

- Add examples to the `examples/` directory for significant features
- Ensure examples compile and run correctly
- Include examples in documentation

### README and Guides

- Update README.md for major features
- Add or update usage guides as needed

## Performance Considerations

dotscope is designed for high performance:

### Memory Usage

- Prefer efficient memory access patterns where possible
- Use memory-mapped files for large assemblies
- Be mindful of allocation patterns

### CPU Performance

- Profile performance-critical code
- Use benchmarks to validate improvements
- Consider parallel processing for batch operations

### Benchmarking

```bash
# Run benchmarks
cargo bench

# Profile with perf (Linux)
cargo build --release
perf record --call-graph=dwarf target/release/examples/basic
perf report
```

## Architecture Guidelines

### Error Handling

- Use the crate's `Error` type consistently
- Provide meaningful error messages
- Include context in error chains

### Module Organization

- Keep modules focused and cohesive
- Use clear naming conventions
- Document module purposes

### Dependencies

- Minimize external dependencies
- Prefer well-maintained crates
- Document why dependencies are needed

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

### Release Checklist

- [ ] Update version in `Cargo.toml`
- [ ] Update `CHANGELOG.md`
- [ ] Ensure all tests pass
- [ ] Run fuzzing tests
- [ ] Update documentation
- [ ] Create release PR
- [ ] Tag release after merge

## Getting Help

### Community

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Documentation**: Check docs.rs/dotscope

### Maintainers

- **Johann Kempter** ([@BinFlip](https://github.com/BinFlip)) - Primary maintainer

## Recognition

Contributors will be recognized in:

- `CONTRIBUTORS.md` file
- Release notes for significant contributions
- GitHub contributor statistics

## License

By contributing to dotscope, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to dotscope! Your efforts help make .NET analysis more accessible and powerful for everyone.
