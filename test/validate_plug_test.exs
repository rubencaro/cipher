alias Cipher, as: C
alias Cipher.ValidatePlug, as: P

defmodule ValidatePlugTest do
  use ExUnit.Case, async: true
  use Plug.Test

  test "validates GET requests" do
    url = "/bogus?p=1"
    conn = conn(:get, url) |> P.call
    assert conn.status == 401

    url = "/bogus?p=1" |> C.sign_url
    conn = conn(:get, url) |> P.call
    assert conn.status != 401
  end

  test "validates POST/PUT requests" do
    raw_body = %{"hola": " qué tal ｸｿ", "ymás": "ymás"}
    encoded_body = raw_body |> Poison.encode!

    url = "/bogus"
    for verb <- [:post, :put] do
      conn = send_body(verb, url, encoded_body)
      assert conn.status == 401
    end

    url = "/bogus"
      |> C.sign_url_from_mapped_body(raw_body)
    for verb <- [:post, :put] do
      conn = send_body(verb, url, encoded_body)
      assert conn.status != 401
    end
  end

  test "calls error_callback" do
    Agent.start(fn()-> :not_set end, name: :cb_test_agent)

    cb = fn(_, _) ->
      Agent.update(:cb_test_agent, fn(_)-> :yay end)
    end

    url = "/bogus?p=1" |> C.sign_url
    conn = conn(:get, url) |> P.call
    assert conn.status != 401
    assert :not_set = Agent.get(:cb_test_agent,&(&1))

    url = "/bogus?p=1"
    conn = conn(:get, url) |> P.call(error_callback: cb)
    assert conn.status == 401
    assert :yay = Agent.get(:cb_test_agent,&(&1))

    url = "/bogus?p=1"
    conn = conn(:get, url) |> P.call(error_callback: cb, test_mode: true)
    assert conn.status != 401
    assert :yay = Agent.get(:cb_test_agent,&(&1))
  end

  test "honors test_mode" do
    url = "/bogus?p=1"
    conn = conn(:get, url) |> P.call
    assert conn.status == 401

    url = "/bogus?p=1" |> C.sign_url
    conn = conn(:get, url) |> P.call(test_mode: true)
    assert conn.status != 401
  end

  defp send_body(verb, url, encoded_body) do
    conn(verb, url)
    |> set_body_params(encoded_body |> Poison.decode!)  # simulate body parsing
    |> P.call
  end

  defp set_body_params(conn, body) do
    %{conn | body_params: body}
  end
end
