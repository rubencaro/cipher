require Cipher.Helpers, as: H  # the cool way

defmodule Cipher do

  @moduledoc """
    Helpers to encrypt and decrypt data.
  """
  # handy to have them around
  @k H.env(:keyphrase) |> Cipher.Digest.generate_key
  @i H.env(:ivphrase) |> Cipher.Digest.generate_iv

  @doc """
    Returns encrypted string containing given `data` string

    ```elixir
    "secret"
    |> Cipher.encrypt  # "KSHHdx0uyveYGY5PHqLAKw%3D%3D"
    |> Cipher.decrypt  # "secret"
    ```
  """
  def encrypt(data) do
    encrypted = :crypto.block_encrypt :aes_cbc128, @k, @i, pad(data)
    encrypted |> Base.encode64 |> URI.encode_www_form
  end

  @doc """
    Returns decrypted string contained in given `crypted` string

    ```elixir
    "secret"
    |> Cipher.encrypt  # "KSHHdx0uyveYGY5PHqLAKw%3D%3D"
    |> Cipher.decrypt  # "secret"
    ```
  """
  def decrypt(crypted) do
    {:ok, decoded} = crypted |> URI.decode_www_form |> Base.decode64
    :crypto.block_decrypt(:aes_cbc128, @k, @i, decoded) |> depad
  end

  @doc """
  Returns the JSON converted and encrypted version of given data:

  ```elixir
  %{"hola": " qué tal ｸｿ"}
  |> Cipher.cipher  # "qW0Voj3h4nglx4NPy8aLXVY5ze5V3OBu5IoaQTMUUbU%3D"
  |> Cipher.parse  #  {:ok, %{"hola" => " qué tal ｸｿ"}}
  ```
  """
  def cipher(data), do: data |> Poison.encode! |> encrypt

  @doc """
    Returns the JSON parsed data of the given crypted string,
    with labeled tuples: `{:ok, data}` or `{:error, reason}`

    ```elixir
    %{"hola": " qué tal ｸｿ"}
    |> Cipher.cipher  # "qW0Voj3h4nglx4NPy8aLXVY5ze5V3OBu5IoaQTMUUbU%3D"
    |> Cipher.parse  #  {:ok, %{"hola" => " qué tal ｸｿ"}}
    ```
  """
  def parse(crypted) do
    try do
      {:ok, crypted |> decrypt |> Poison.decode!}
    rescue
      reason -> {:error, reason}
    end
  end

  @doc """
    Gets signature for given `base` and appends as a param to `url`.
    Returns `url` with appended param.
    Given `payload` is contained within the signature and will be
  """
  def sign(url, base), do: sign(url, base, %{})
  def sign(url, base, payload) when is_list(payload),
    do: sign(url, base, Enum.into(payload, %{}))
  def sign(url, base, payload) when is_map(payload) do
    nexus = if String.contains?(url, "?"), do: "&", else: "?"
    signature = :crypto.hash(:md5, base) |> Cipher.Digest.hexdigest
    {_, _, micros} = :os.timestamp
    pepper = micros |> Integer.to_string |> String.rjust(8) # 8 characters long
    data = payload |> Map.merge(%{md5: signature <> pepper})
    url <> nexus <> "signature=" <> cipher(data)
  end

  @doc """
    An URL is signed by getting a hash from it, ciphering that hash,
    and appending it as the last query parameter.
  """
  def sign_url(url, payload \\ %{}), do: sign(url, url, payload)

  @doc """
    The URL is signed by getting a MD5 hash from the sorted data values, ciphering that hash,
    and appending it as the last query parameter of the URL.
  """
  def sign_url_from_body(url, body, payload \\ %{}), do: sign(url, body, payload)

  @doc """
    Decrypts `ciphered`, and compare with an MD5 hash got from base.
    Returns false if decryption failed, or if comparison failed.
    Whatever parsed otherwise.
  """
  def validate_signature(ciphered, base, rest) do
    case parse(ciphered) do
      {:ok, parsed} -> validate_parsed_signature(parsed, base, rest)
      any -> any
    end
  end

  defp validate_parsed_signature(parsed, base, rest) do
    ignored = parsed |> Map.get("ignore", [])
    rest = rest |> String.split("&", trim: true)
    case validate_ignored(ignored, rest) do
      :ok -> validate_base(parsed, base)
      any -> any
    end
  end

  defp validate_ignored(_, []), do: :ok
  defp validate_ignored(ignored, [r | rest]) do
    n = r |> String.split("=") |> List.first
    case n in ignored do
      true -> validate_ignored(ignored, rest)
      false -> {:error, "Not ignored or signed: #{r}"}
    end
  end

  defp validate_base(parsed, base) do
    signature = :crypto.hash(:md5, base)
                |> Cipher.Digest.hexdigest
    read_signature = String.slice(parsed["md5"], 0..-9) # removing pepper from parsed
    case signature == read_signature do
      true -> {:ok, parsed}
      false -> {:error, "Bad signature"}
    end
  end

  @doc """
    Pop the last parameter, which must be `signature`,
    get an MD5 hash of the remains,
    decrypt popped value, and compare with the MD5 hash
  """
  def validate_signed_url(url) do
    {clean_url, popped, rest} = pop_signature(url)
    validate_magic_token(popped, clean_url, rest)
  end

  @doc """
    Pop the last parameter from the URL, decrypt it,
    get an MD5 of the body, and compare with the decrypted value
  """
  def validate_signed_body(url, body) do
    {_, popped, rest} = pop_signature(url)
    validate_magic_token(popped, body, rest)
  end

  defp validate_magic_token(popped, base, rest) do
    case popped == H.env(:magic_token) do
      true -> {:ok, %{}}
      false -> validate_signature(popped, base, rest)
    end
  end

  # Pad given string until its length is divisible by 16.
  # It uses PKCS#7 padding.
  #
  defp pad(str, block_size \\ 16) do
    len = byte_size(str)
    utfs = len - String.length(str) # UTF chars are 2byte, ljust counts only 1
    pad_len = block_size - rem(len, block_size) - utfs
    String.ljust(str, len + pad_len, pad_len) # PKCS#7 padding
  end

  # Remove PKCS#7 padding from given string.
  defp depad(str) do
    <<last>> = String.last str
    String.rstrip str, last
  end

  # Pops the signature param, which must be the last one.
  # Returns the remaining url and the popped signature.
  #
  defp pop_signature(url) do
    case String.split(url, "signature=") do
      [dirty_url, popped] -> pop_signature(dirty_url, popped)
      _ -> {url, "", ""}
    end
  end
  defp pop_signature(dirty_url, popped) do
    clean_url = String.slice(dirty_url, 0..-2)
    case String.split(popped, "&") do
      [signature, rest] -> {clean_url, signature, rest}
      _ -> {clean_url, popped, ""}
    end
  end

end
