# mdcrypt

A Rust library for encryption, error checking and more. Now this library contains:

- `Vigener` - for Vigener encryption
- `Hamming` - Hamming error correction code
- `Sha224`, `Sha256`, `Sha384`, `Sha512` - the SHA2 family

## Documentation

Documentation can be generated. Steps to generate it:

```shell
# 1. Download the GitHub repository:
git clone https://github.com/dousamichal0807/mdcrypt.git
# 2. Navigate into the repository
cd mdswp
# 3. Channge branch from development to a stable branch, for example:
git checkout v0.2.0
# 4. Generate documentation:
cargo doc --release --no-deps
```

Now, documentation is generated in `target/doc` directory. You can open `index.html` from there in your browser to see mdcrypt's documentation.

## Usage

It is recommended to use it in your `Cargo.toml` like this:

```toml
[dependencies]
mdcrypt = { git = "https://github.com/dousamichal0807/mdcrypt.git", branch = "v0.2.0" }
# your other dependencies here
```

You can use other branch, as well.