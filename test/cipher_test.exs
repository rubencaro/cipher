require Cipher.Helpers, as: H  # the cool way

defmodule CipherTest do
  use ExUnit.Case, async: true
  alias Cipher, as: C

  test "the whole encrypt/decrypt stack" do
    s = Poison.encode! %{"hola": " qué tal ｸｿ"}
    assert s == s |> C.encrypt |> C.decrypt

    assert {:error, _} = "random" |> C.decrypt    # decode fails
    assert {:error, _} = "nonsense" |> C.decrypt  # decrypt fails
  end

  test "whitespace at end of message encrypted/decrypted" do
    s = "               "
    assert s == s |> C.encrypt |> C.decrypt
  end

  test "parse ciphered hash" do
    h = %{"hola" => " qué tal ｸｿ"}
    s = Poison.encode! h

    assert {:ok, ^h} = s |> C.encrypt |> C.parse
    assert {:error, _} = "very invalid" |> C.parse
    assert {:error, _} = (C.encrypt(s) <> "slightly invalid") |> C.parse
  end

  test "get ciphered hash" do
    h = %{"hola": " qué tal ｸｿ"}
    s = h |> Poison.encode! |> C.encrypt
    assert C.cipher(h) == s
  end

  test "validate_signed_url" do
    # ok with regular urls
    url = "/bla/bla"
    assert {:ok, _} = "#{url}" |> C.sign_url |> C.validate_signed_url
    assert {:ok, _} = "#{url}?sdfasdf=sdfgadf&dsfasdf=addfga" |> C.sign_url |> C.validate_signed_url

    # not signed and wrongly signed fails
    assert {:error, _} = "#{url}" |> C.validate_signed_url
    assert {:error, _} = "#{url}?signature=badhash" |> C.validate_signed_url
    assert {:error, _} = "#{url}?asdkjh=sdfklh&signature=badhash" |> C.validate_signed_url
  end

  test "it works ignoring some too" do
    url = "/bla/bla"
    s = "#{url}" |> C.sign_url(deny: ["source", "source2"])
    assert {:ok, _} = C.validate_signed_url(s)
    assert {:ok, _} = C.validate_signed_url(s <> "&other=crappysource")
    assert {:error, _} = C.validate_signed_url(s <> "&source=crappysource&source2=crappysecondsource")
  end

  test "Magic Token works with url" do
    url = "/bla/bla"
    assert {:ok, _} = "#{url}?a=123&signature=#{H.env(:magic_token)}" |> C.validate_signed_url
    assert {:error, _} = "#{url}?a=123&signature=#{H.env(:magic_token)}X" |> C.validate_signed_url
  end

  test "Magic Token works with body" do
    url = "/bla/bla"
    body = Poison.encode! %{"hola": " qué tal ｸｿ"}
    assert {:ok, _} = "#{url}?a=123&signature=#{H.env(:magic_token)}" |> C.validate_signed_body(body)
    assert {:error, _} = "#{url}?a=123&signature=#{H.env(:magic_token)}X" |> C.validate_signed_body(body)
  end

  test "validate_signed_body" do
    url = "/bla/bla"
    body = Poison.encode! %{"hola": " qué tal ｸｿ"}
    assert {:error, _} = "#{url}" |> C.validate_signed_body(body)
    assert {:error, _} = "#{url}?signature=badhash" |> C.validate_signed_body(body)
    assert {:error, _} = "#{url}?asdkjh=sdfklh&signature=badhash" |> C.validate_signed_body(body)
    assert {:ok, _} = "#{url}" |> C.sign_url_from_body(body) |> C.validate_signed_body(body)
  end

  test "signing body also denies params" do
    url = "/bla/bla"
    body = Poison.encode! %{"hola": " qué tal ｸｿ"}
    signed = C.sign_url_from_body(url, body, deny: ["cb"])
    assert {:ok, _} = "#{signed}" |> C.validate_signed_body(body)
    assert {:ok, _} = "#{signed}&other=123456" |> C.validate_signed_body(body)
    assert {:error, _} = "#{signed}&cb=123456" |> C.validate_signed_body(body)
    assert {:error, _} = "#{signed}&cb=123456&other=any" |> C.validate_signed_body(body)
  end

  test "Magic Token works with signed mapped body" do
    url = "/bla/bla"
    body = %{"hola": " qué tal ｸｿ"} |> Poison.encode! |> Poison.decode!
    assert {:ok, _} = "#{url}?a=123&signature=#{H.env(:magic_token)}" |> C.validate_signed_body(body)
    assert {:error, _} = "#{url}?a=123&signature=#{H.env(:magic_token)}X" |> C.validate_signed_body(body)
  end

  test "validate_signed_mapped_body" do
    url = "/bla/bla"
    # body is signed, then JSON encoded, then sent, then JSON decoded, then validated
    raw_body = %{"hola": " qué tal ｸｿ", "ymás": "ymás"}
    body = raw_body |> Poison.encode! |> Poison.decode!
    assert {:error, _} = "#{url}" |> C.validate_signed_body(body)
    assert {:error, _} = "#{url}?signature=badhash" |> C.validate_signed_body(body)
    assert {:error, _} = "#{url}?asdkjh=sdfklh&signature=badhash" |> C.validate_signed_body(body)
    assert {:ok, _} = "#{url}" |> C.sign_url_from_mapped_body(raw_body) |> C.validate_signed_body(body)
    # reordered works the same
    raw_body = %{"ymás": "ymás", "hola": " qué tal ｸｿ"}
    assert {:ok, _} = "#{url}" |> C.sign_url_from_mapped_body(raw_body) |> C.validate_signed_body(body)
  end

  test "signing mapped body also denies params" do
    url = "/bla/bla"
    # body is signed, then JSON encoded, then sent, then JSON decoded, then validated
    raw_body = %{"hola": " qué tal ｸｿ"}
    body = raw_body |> Poison.encode! |> Poison.decode!
    signed = C.sign_url_from_mapped_body(url, raw_body, deny: ["cb"])
    assert {:ok, _} = "#{signed}" |> C.validate_signed_body(body)
    assert {:ok, _} = "#{signed}&other=123456" |> C.validate_signed_body(body)
    assert {:error, _} = "#{signed}&cb=123456" |> C.validate_signed_body(body)
    assert {:error, _} = "#{signed}&cb=123456&other=any" |> C.validate_signed_body(body)
  end

  test "remove carry return character" do
    signed_url = ("/bla/bla?p1=1&p2=2" |> Cipher.sign_url) <> "%0A"
    assert {:ok, _} = Cipher.validate_signed_url(signed_url)
  end

  test "remove carry return character when there is rest field" do
    url = "/bla/bla"
    s = "#{url}" |> C.sign_url()
    s = s <> "%0A&source=crappysource&source2=crappysecondsource"
    assert {:ok, _} = C.validate_signed_url(s)
  end

end
