# Contributing to Reconx

Thank you for your interest in contributing to Reconx! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/Reconx.git`
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run clippy: `cargo clippy -- -D warnings`
7. Commit: `git commit -m "feat: description of change"`
8. Push and open a Pull Request

## Development Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build

# Run tests
cargo test

# Run with verbose output
cargo run -- enum -d example.com -v
```

## Adding a New Collector

1. Create a new file in `src/collectors/` (e.g., `my_source.rs`)
2. Implement the `Collector` trait:

```rust
use async_trait::async_trait;
use crate::collectors::{Collector, CollectorCategory};
use crate::config::Config;
use crate::error::Result;
use crate::models::{Finding, Target};

pub struct MySourceCollector;

#[async_trait]
impl Collector for MySourceCollector {
    fn name(&self) -> &str { "my_source" }
    fn category(&self) -> CollectorCategory { CollectorCategory::DnsSubdomain }
    fn requires_api_key(&self) -> bool { false }

    async fn collect(&self, target: &Target, config: &Config) -> Result<Vec<Finding>> {
        // Your implementation here
        Ok(Vec::new())
    }
}
```

3. Register it in `src/collectors/mod.rs`
4. Add a unit test in the same file or in `tests/`

## Code Style

- Follow standard Rust conventions (`rustfmt`)
- All public functions should have doc comments
- New features should include tests
- Keep collector implementations self-contained
- Use `thiserror` for error types

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `test:` — Adding or updating tests
- `refactor:` — Code refactoring
- `style:` — Code style changes (formatting, etc.)

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include the output of `reconx --version`
- For bugs, include steps to reproduce and expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
