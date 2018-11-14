# AESCrypt

Read and write files in [AES Crypt format](https://www.aescrypt.com/aes_file_format.html).

## Usage

```elixir
iex(1)> AESCrypt.write("example.aes", "Hello, world!", "supersecret")
:ok
iex(2)> AESCrypt.read("example.aes", "supersecret")
{:ok, "Hello, world!", [{"CREATED_BY", "Elixir AESCrypt v0.1.0"}]}
iex(3)> AESCrypt.read!("example.aes", "supersecret")
"Hello, world!"
```

## Limitations

* Supports v2 format only
* Decrypts/encrypts entire contents in memory; no streaming
* No attempts are made to protect keying material: the passphrase, derived key,
  file-specific key and plaintext may leak in stack traces, crashdumps, or
  BEAM introspection functions

## Installation

The package can be installed by adding `aes_crypt` to your list of dependencies
in `mix.exs`:

```elixir
def deps do
  [
    {:aes_crypt, "~> 0.1.0"}
  ]
end
```

Documentation can be found at [https://hexdocs.pm/aes_crypt](https://hexdocs.pm/aes_crypt).
