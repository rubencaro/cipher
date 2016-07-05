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
  def encrypt(data) when is_binary(data) do
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

    Returns `{:error, "Could not decode string 'yourstring'"}` if it failed in
    the first stage of decryption (unescaping and decoding given string). That
    means someone tampered your crypted data, or maybe the crypted string was
    not transferred properly.

    Returns `{:error, "Could not decrypt string 'yourstring'"}` if it failed in
    the last stage, the decryption itself. Usually means your decryption keys are
    not the same that were used to encrypt. But may also be some cases were a
    tampered or wrongly transferred string can be actually unescaped and decoded
    successfully. They will fail in the decryption stage.
  """
  def decrypt(crypted) when is_binary(crypted) do
    try do
      {:ok, decoded} = crypted |> URI.decode_www_form |> Base.decode64
      do_decrypt(decoded)
    rescue
      _ -> {:error, "Could not decode string '#{crypted}'"}
    end
  end

  defp do_decrypt(decoded) do
    try do
      :crypto.block_decrypt(:aes_cbc128, @k, @i, decoded) |> depad
    rescue
      _ -> {:error, "Could not decrypt string '#{decoded}'"}
    end
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
    case crypted |> decrypt do
      {:error, reason} -> {:error, reason}
      decrypted -> Poison.decode(decrypted)
    end
  end

  @doc """
    Gets signature for given `base` and appends as a param to `url`.
    Returns `url` with appended param.
    Given `payload` is contained within the signature and will be returned
    by `validate_signature/3`.

    Be aware that `payload` must be a `Map`, and that some keys, such as
    `md5` or `deny`, will be used internally. Keep things namespaced in there
    and there will be no collisions.
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

    ```elixir
    "/bla/bla?p1=1&p2=2"
    |> Cipher.sign_url  # "/bla/bla?p1=1&p2=2&signature=4B6WOiuD9N39K7p%2BnqNIljGh5F%2F%2BnHRQGZC9ih%2Bh%2BHGZc8Tz0KdRJXC%2B5M%2B8%2BHZ2mAXPh3jQcSRieTq4dGm5Ng%3D%3D"
    ```
  """
  def sign_url(url, payload \\ %{}), do: sign(url, url, payload)

  @doc """
    The URL is signed by getting a MD5 hash from the sorted data values, ciphering that hash,
    and appending it as the last query parameter of the URL.
  """
  def sign_url_from_body(url, body, payload \\ %{}), do: sign(url, body, payload)

  @doc """
    The URL is signed by getting a MD5 hash from the sorted data values, ciphering that hash,
    and appending it as the last query parameter of the URL.

    The given mapped_body must be a map.
  """
  def sign_url_from_mapped_body(url, mapped_body, payload \\ %{}) when is_map(mapped_body) do
    base = mapped_body |> to_base
    sign(url, base, payload)
  end

  # Generate a cipherable base from given `data`, being `data` any erlang term.
  # This should be the same for every term with the same data, no matter the order.
  # Get every key and value from given map, sort them alphabetically, and the join them.
  #
  # If `data` is a map, then it is sorted first, then converted to binary.
  #
  defp to_base(data) when is_map(data) do
    data
    |> Enum.sort
    |> Enum.map_join(fn({k,v})-> "#{to_base(k)}#{to_base(v)}" end)
  end
  defp to_base(data), do: data |> to_string

  @doc """
    Decrypts `ciphered`, and compare with an MD5 hash got from base.
    Returns `{:error, reason}` if decryption failed, or if comparison failed.
    `{:ok, payload}` otherwise.
  """
  def validate_signature(ciphered, base, rest) do
    case parse(ciphered) do
      {:ok, parsed} -> validate_parsed_signature(parsed, base, rest)
      any -> any
    end
  end

  # Check if parsed data looks good, then go on validating base.
  #
  defp validate_parsed_signature(parsed, base, rest) do
    denied = parsed |> Map.get("deny", [])
    rest = rest |> String.split("&", trim: true)
    case validate_denied(denied, rest) do
      :ok -> validate_base(parsed, base)
      any -> any
    end
  end

  # Check if every extra param was explicitly denied
  #
  defp validate_denied(_, []), do: :ok
  defp validate_denied(denied, [r | rest]) do
    n = r |> String.split("=") |> List.first
    case n in denied do
      true -> {:error, "Denied: #{r}"}
      false -> validate_denied(denied, rest)
    end
  end

  # Check if signature (which is derived from `base`) matches the one in `parsed`
  #
  defp validate_base(parsed, base) when is_binary(base) do
    signature = :crypto.hash(:md5, base)
                |> Cipher.Digest.hexdigest
    read_signature = String.slice(parsed["md5"], 0..-9) # removing pepper from parsed
    case signature == read_signature do
      true -> {:ok, parsed}
      false -> {:error, "Bad signature"}
    end
  end
  defp validate_base(parsed, mapped_body) do
    base = mapped_body |> to_base
    validate_base(parsed, base)
  end

  @doc """
    Validate given signed URL.

    ```elixir
    "/bla/bla?p1=1&p2=2&signature=4B6WOiuD9N39K7p%2BnqNIljGh5F%2F%2BnHRQGZC9ih%2Bh%2BHGZc8Tz0KdRJXC%2B5M%2B8%2BHZ2mAXPh3jQcSRieTq4dGm5Ng%3D%3D"
    |> Cipher.validate_signed_url  # {:ok, %{"md5" => "86e359da7ab4886f3525ac2b9c5edc5b  613146"}}
    ```

    `{:ok, payload}` or `{:error, reason}` are returned.
  """
  def validate_signed_url(url) do
    {clean_url, popped, rest} = pop_signature(url)
    validate_magic_token(popped, clean_url, rest)
  end

  @doc """
    Validate given signed URL + body.
    If body is a binary, it will be validated as if signed using `sign_url_from_body/2`.
    Else it will be validated as if signed using `sign_url_from_mapped_body/2`.

    `{:ok, payload}` or `{:error, reason}` are returned.
  """
  def validate_signed_body(url, body) do
    {_, popped, rest} = pop_signature(url)
    validate_magic_token(popped, body, rest)
  end

  # First check magic token presence, then go on validating.
  #
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
  #
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
    case String.split(popped, "&", parts: 2) do
      [signature, rest] -> {clean_url, clean_invalid_characters(signature), rest}
      _ -> {clean_url, clean_invalid_characters(popped), ""}
    end
  end

  # Cleans invalid characters from the given url.
  #
  defp clean_invalid_characters(url) do
    url
      |> String.replace("%0A", "")
      |> String.replace("%0a", "")
  end

end
