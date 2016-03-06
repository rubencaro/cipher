require Cipher.Helpers, as: H  # the cool way

defmodule CipherTest do
  use ExUnit.Case, async: true
  alias Cipher, as: C

  test "the whole encrypt/decrypt stack" do
    s = Poison.encode! %{"hola": " qué tal ｸｿ"}
    assert s == s |> C.encrypt |> C.decrypt
  end

  test "parse ciphered hash" do
    h = %{"hola" => " qué tal ｸｿ"}
    s = Poison.encode! h

    assert {:ok, ^h} = s |> C.encrypt |> C.parse
    assert {:error, _} = 'very invalid' |> C.parse
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
    H.spit("#{url}" |> C.sign_url |> C.validate_signed_url)
    assert {:ok, _} = "#{url}" |> C.sign_url |> C.validate_signed_url
    assert "#{url}?sdfasdf=sdfgadf&dsfasdf=addfga" |> C.sign_url |> C.validate_signed_url

    # not signed and wrongly signed fails
    refute "#{url}" |> C.validate_signed_url
    refute "#{url}?signature=badhash" |> C.validate_signed_url
    refute "#{url}?asdkjh=sdfklh&signature=badhash" |> C.validate_signed_url
  end

  test "it works ignoring some too" do
    url = "/bla/bla"
    s = "#{url}" |> C.sign_url(ignored: ["source"])
    assert C.validate_signed_url(s)
    assert C.validate_signed_url(s <> "&source=crappysource")
    refute C.validate_signed_url(s <> "&other=crappysource")
  end

  test "Magic Token works with url" do
    url = "/bla/bla"
    assert "#{url}?a=123&signature=#{H.env(:magic_token)}" |> C.validate_signed_url
    refute "#{url}?a=123&signature=#{H.env(:magic_token)}X" |> C.validate_signed_url
  end

  test "Magic Token works with body" do
    url = "/bla/bla"
    body = Poison.encode! %{"hola": " qué tal ｸｿ"}
    assert "#{url}?a=123&signature=#{H.env(:magic_token)}" |> C.validate_signed_body(body)
    refute "#{url}?a=123&signature=#{H.env(:magic_token)}X" |> C.validate_signed_body(body)
  end

  test "validate_signed_body" do
    url = "/bla/bla"
    body = Poison.encode! %{"hola": " qué tal ｸｿ"}
    refute "#{url}" |> C.validate_signed_body(body)
    refute "#{url}?signature=badhash" |> C.validate_signed_body(body)
    refute "#{url}?asdkjh=sdfklh&signature=badhash" |> C.validate_signed_body(body)
    assert "#{url}" |> C.sign_url_from_body(body) |> C.validate_signed_body(body)
  end

end
