defmodule CipherTest do
  use ExUnit.Case, async: true
  alias Cipher, as: C

  test "the whole encrypt/decrypt stack" do
    s = "hola qué tal ｸｿ"
    assert s == s |> C.encrypt(k,i) |> C.decrypt(k,i)
  end

  test "url signature" do
    # ok with regular urls
    url = "/blab/bla"
    assert url |> C.sign_url(k,i) |> C.validate_signed_url(k,i)
    url = "/blab/bla?sdfgsdf=dfgsd"
    assert url |> C.sign_url(k,i) |> C.validate_signed_url(k,i)

    # not signed fails
    url = "/blab/bla"
    refute C.validate_signed_url(url,k,i)

    # bad signature fails
    signed = url <> "?signature=badhash"
    refute C.validate_signed_url(signed,k,i)
  end

  # handy to have them around
  defp k, do: "testiekeyphraseforcipher"|> C.generate_key
  defp i, do: "testieivphraseforcipher" |> C.generate_iv

end
