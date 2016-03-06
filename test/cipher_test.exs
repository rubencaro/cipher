defmodule CipherTest do
  use ExUnit.Case, async: true
  alias Cipher, as: C

  test "the whole encrypt/decrypt stack" do
    s = Poison.encode! %{"hola": " qué tal ｸｿ"}
    assert s == s |> C.encrypt(k,i) |> C.decrypt(k,i)
  end

  test "parse ciphered hash" do
    h = %{"hola": " qué tal ｸｿ"}
    s = Poison.encode! h

    res = s |> C.encrypt(k,i) |> C.parse(k,i)
    assert res.valid
    assert res.data == h

    res = C.parse 'very invalid', k, i)
    refute res.valid

    res = C.parse(C.encrypt(s,k,i)) <> "slightly invalid", k, i)
    refute res.valid
  end

  test "get ciphered hash" do
    h = %{"hola": " qué tal ｸｿ"}
    s = h |> Poison.encode! |> C.encrypt
    assert C.cipher(h) == s
  end

  test "validate_signed_url" do
    # ok with regular urls
    assert "/bla/bla" |> C.sign_url(k,i) |> C.validate_signed_url(k,i)
    assert "/bla/bla?sdfasdf=sdfgadf&dsfasdf=addfga" |> C.sign_url(k,i) |> C.validate_signed_url(k,i)

    # not signed and wrongly signed fails
    refute "/bla/bla" |> C.validate_signed_url(k,i)
    refute "/bla/bla?signature=badhash" |> C.validate_signed_url(k,i)
    refute "/bla/bla?asdkjh=sdfklh&signature=badhash" |> C.validate_signed_url(k,i)
  end

  test "it works ignoring some too" do
    s = "/bla/bla" |> C.sign_url(k, i, ignored: ["source"])
    assert C.validate_signed_url(s, k, i)
    assert C.validate_signed_url(s <> "&source=crappysource", k, i)
    refute C.validate_signed_url(s <> "&other=crappysource", k, i)
  end

  test "Magic Token works" do
    assert "/bla/bla?a=123&signature=#{C.magic_token}" |> C.validate_signed_url(k,i)
    refute "/bla/bla?a=123&signature=#{C.magic_token}X" |> C.validate_signed_url(k,i)
  end

  test "validate_signed_body" do
    body = Poison.encode! %{"hola": " qué tal ｸｿ"}
    
  end

  # handy to have them around
  defp k, do: "testiekeyphraseforcipher"|> C.generate_key
  defp i, do: "testieivphraseforcipher" |> C.generate_iv

end
