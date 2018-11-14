defmodule AESCrypt do
  @moduledoc """
  Read and write files in AES Crypt format.
  """
  defmodule Error do
    defexception [:message]
  end

  @version 2
  @created_by "Elixir AESCrypt v#{AESCrypt.Mixfile.project()[:version]}"
  @placeholder_len 128

  @doc """
  Attempts to read and decrypt the file at the specified location.

  Returns `{:ok, plaintext, extensions}` upon success, or `{:error, reason}`
  in case of failure.
  """
  def read(path, passphrase) do
    with {:ok, data} <- File.read(path),
         {:ok, data} <- verify_header(data),
         {:ok, extensions, data} <- get_extensions(data),
         {:ok, key, iv, data} <- get_key_iv(data, passphrase),
         {:ok, blocks, length, hmac} <- get_data(data),
         :ok <- verify(blocks, key, hmac) do
      plaintext = decrypt(blocks, key, iv, length)
      {:ok, plaintext, extensions}
    end
  end

  @doc """
  Attempts to read and decrypt the file at the specified location. Raises in
  case of failure.

  Returns the plaintext only upon success.
  """
  def read!(path, passphrase) do
    case read(path, passphrase) do
      {:ok, plaintext, _extensions} ->
        plaintext

      {:error, reason} when is_atom(reason) ->
        raise File.Error,
          reason: reason,
          action: "write to file",
          path: IO.chardata_to_string(path)

      {:error, message} ->
        raise Error, message
    end
  end

  @doc """
  Encrypts the content and writes the result to a file at the specified
  location.

  Returns `:ok` upon success, or `{:error, reason}` in case of failure.
  """
  def write(path, content, passphrase, modes \\ []) do
    key = :crypto.strong_rand_bytes(32)
    iv = :crypto.strong_rand_bytes(16)
    size_mod_16 = Integer.mod(byte_size(content), 16)

    ciphertext =
      if size_mod_16 == 0 do
        :crypto.block_encrypt(:aes_cbc, key, iv, content)
      else
        :crypto.block_encrypt(:aes_cbc, key, iv, [
          content,
          String.duplicate("\0", 16 - size_mod_16)
        ])
      end

    hmac = :crypto.hmac(:sha256, key, ciphertext)
    iv1 = :crypto.strong_rand_bytes(16)
    key1 = kdf(iv1, passphrase)
    key_and_iv = :crypto.block_encrypt(:aes_cbc, key1, iv1, [iv, key])
    hmac1 = :crypto.hmac(:sha256, key1, key_and_iv)
    created_by = ["CREATED_BY", @created_by] |> Enum.join("\0")

    File.write(
      path,
      [
        # File signature
        <<"AES", @version::size(8), 0::size(8)>>,
        # CREATED_BY extension
        <<byte_size(created_by)::size(16)-big, created_by::binary>>,
        # Placeholder extension
        <<@placeholder_len::size(16)-big, 0::size(@placeholder_len)-unit(8)>>,
        # End of extensions
        <<0::size(16)>>,
        # IV, encrypted IV + key and HMAC
        iv1,
        key_and_iv,
        hmac1,
        # Ciphertext
        ciphertext,
        # Trailer
        <<size_mod_16::integer-size(8)>>,
        hmac
      ],
      modes
    )
  end

  @doc """
  Encrypts the content and writes the result to a file at the specified
  location. Raises in case of failure.
  """
  def write!(path, content, passphrase, modes \\ []) do
    case write(path, content, passphrase, modes) do
      :ok ->
        :ok

      {:error, reason} when is_atom(reason) ->
        raise File.Error, reason: reason, action: "read file", path: IO.chardata_to_string(path)

      {:error, message} ->
        raise Error, message
    end
  end

  #
  # Private helpers
  #

  defp verify_header(<<"AES", @version::size(8), _::size(8), rest::binary>>) do
    {:ok, rest}
  end

  defp verify_header(<<"AES", version::size(8), _::size(8), _rest::binary>>) do
    {:error, "unsupported version (#{version})"}
  end

  defp verify_header(_data) do
    {:error, "bad header"}
  end

  defp get_extensions(data, acc \\ [])

  defp get_extensions(<<0x0000::size(16), rest::binary>>, acc) do
    {:ok, Enum.reverse(acc), rest}
  end

  defp get_extensions(<<tag_len::size(16)-big, tag::binary-size(tag_len), rest::binary>>, acc) do
    case String.split(tag, "\0", parts: 2) do
      ["", _] ->
        # Ignore empty placeholder extension
        get_extensions(rest, acc)

      [key, value] ->
        get_extensions(rest, [{key, value} | acc])
    end
  end

  defp get_extensions(_data, _acc) do
    {:error, "bad header"}
  end

  defp get_key_iv(
         <<iv1::binary-size(16), key_and_iv::binary-size(48), hmac::binary-size(32),
           rest::binary>>,
         passphrase
       ) do
    key1 = kdf(iv1, passphrase)

    if :crypto.hmac(:sha256, key1, key_and_iv) == hmac do
      <<iv::binary-size(16), key::binary-size(32)>> =
        :crypto.block_decrypt(:aes_cbc, key1, iv1, key_and_iv)

      {:ok, key, iv, rest}
    else
      {:error, "incorrect passphrase"}
    end
  end

  defp get_key_iv(_data, _passphrase) do
    {:error, "bad header"}
  end

  defp get_data(data) when byte_size(data) >= 33 do
    blocks = Integer.floor_div(byte_size(data), 16) - 2
    ciphertext_size = blocks * 16

    case data do
      <<ciphertext::binary-size(ciphertext_size), size_mod_16::integer-size(8),
        hmac::binary-size(32)>> ->
        length =
          if size_mod_16 == 0 do
            ciphertext_size
          else
            ciphertext_size - 16 + size_mod_16
          end

        {:ok, ciphertext, length, hmac}

      _else ->
        {:error, "file corrupted"}
    end
  end

  defp verify(ciphertext, key, hmac) do
    if :crypto.hmac(:sha256, key, ciphertext) == hmac do
      :ok
    else
      {:error, "file integrity check failed"}
    end
  end

  defp decrypt(ciphertext, key, iv, length) do
    :crypto.block_decrypt(:aes_cbc, key, iv, ciphertext)
    |> binary_part(0, length)
  end

  defp kdf(iv, passphrase) do
    passphrase_utf16 =
      passphrase
      |> to_charlist()
      |> :unicode.characters_to_binary(:utf8, {:utf16, :little})

    seed = iv <> String.duplicate("\0", 16)

    Enum.reduce(1..8192, seed, fn _, digest ->
      :crypto.hash(:sha256, digest <> passphrase_utf16)
    end)
  end
end
