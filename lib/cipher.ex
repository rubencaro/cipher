
defmodule Cipher do

  @moduledoc """
    Helpers to encrypt and decrypt data.
  """

  @doc """
    Returns encrypted string containing given `data` string, using given `key`
    and `iv`.
    Suitable `key` and `iv` can be generated with `generate_key/1`
    and `generate_iv/1`.
  """
  def encrypt(data, key, iv) do
    encrypted = :crypto.block_encrypt :aes_cbc128, key, iv, pad(data)
    encrypted |> Base.encode64 |> URI.encode_www_form
  end

  @doc """
    Returns decrypted string contained in given `crypted` string, using given
    `key` and `iv`.
    Suitable `key` and `iv` can be generated with `generate_key/1`
    and `generate_iv/1`.
  """
  def decrypt(crypted, key, iv) do
    {:ok, decoded} = crypted |> URI.decode_www_form |> Base.decode64
    :crypto.block_decrypt(:aes_cbc128, key, iv, decoded) |> depad
  end

  @doc "Generates a suitable key for encryption based on given `phrase`"
  def generate_key(phrase) do
    :crypto.hash(:sha, phrase) |> hexdigest |> String.slice(0,16)
  end

  @doc "Generates a suitable iv for encryption based on given `phrase`"
  def generate_iv(phrase), do: phrase |> String.slice(0,16)

  @doc "Gets an usable string from a binary crypto hash"
  def hexdigest(binary) do
    :lists.flatten(for b <- :erlang.binary_to_list(binary),
        do: :io_lib.format("~2.16.0B", [b]))
    |> :string.to_lower
    |> List.to_string
  end

  @doc """
    Pad given string until its length is divisible by 16.
    It uses PKCS#7 padding.
  """
  def pad(str, block_size \\ 16) do
    len = byte_size(str)
    utfs = len - String.length(str) # UTF chars are 2byte, ljust counts only 1
    pad_len = block_size - rem(len, block_size) - utfs
    String.ljust(str, len + pad_len, pad_len) # PKCS#7 padding
  end

  @doc "Remove PKCS#7 padding from given string."
  def depad(str) do
    <<last>> = String.last str
    String.rstrip str, last
  end

  @doc """
    Gets signature for given `base` and appends as a param to `url`.
    Returns `url` with appended param.
  """
  def sign(url, base, key, iv) do
    nexus = if String.contains?(url, "?"), do: "&", else: "?"
    signature = :crypto.hash(:md5, base) |> hexdigest
    {_, _, micros} = :os.timestamp
    pepper = micros |> Integer.to_string |> String.rjust(8) # 8 characters long
    crypted = signature <> pepper |> encrypt(key, iv)
    url <> nexus <> "signature=" <> crypted
  end

  @doc """
    An URL is signed by getting a hash from it, ciphering that hash,
    and appending it as the last query parameter.
  """
  def sign_url(url, key, iv), do: sign(url, url, key, iv)

  @doc """
    Pops the signature param, which must be the last one.
    Returns the remaining url and the popped signature.
  """
  def pop_signature(url) do
    case String.split(url, "signature=") do
      [dirty_url, popped] ->
              clean_url = String.slice dirty_url, 0..-2 # remove nexus
              {clean_url, popped}
      _ -> {url, ""}
    end
  end

  @doc """
    Decrypts `ciphered`, and compare with an MD5 hash got from base.
    Returns false if decryption failed, or if comparison failed. True otherwise.
  """
  def validate_signature(ciphered, base, key, iv) do
    try do
      plain = decrypt(ciphered, key, iv)
      signature = :crypto.hash(:md5, base) |> hexdigest
      signature == String.slice(plain, 0..-9) # removing pepper from parsed
    rescue
      _ -> false
    end
  end

  @doc """
    Pop the last parameter, which must be `signature`,
    get an MD5 hash of the remains,
    decrypt popped value, and compare with the MD5 hash
  """
  def validate_signed_url(url, key, iv) do
    {clean_url, popped} = pop_signature(url)
    validate_signature(popped, clean_url, key, iv)
  end

end
