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
    s = "#{url}" |> C.sign_url(ignore: ["source"])
    assert {:ok, _} = C.validate_signed_url(s)
    assert {:ok, _} = C.validate_signed_url(s <> "&source=crappysource")
    assert {:error, _} = C.validate_signed_url(s <> "&other=crappysource")
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

  test "signing body also ignores params" do
    url = "/bla/bla"
    body = Poison.encode! %{"hola": " qué tal ｸｿ"}
    signed = C.sign_url_from_body(url, body, ignore: ["cb"])
    assert {:ok, _} = "#{signed}" |> C.validate_signed_body(body)
    assert {:ok, _} = "#{signed}&cb=123456" |> C.validate_signed_body(body)
    assert {:error, _} = "#{signed}&other=123456" |> C.validate_signed_body(body)
    assert {:error, _} = "#{signed}&cb=123456&other=any" |> C.validate_signed_body(body)
  end

end
