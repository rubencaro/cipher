# Cipher

[![Build Status](https://api.travis-ci.org/rubencaro/cipher.svg)](https://travis-ci.org/rubencaro/cipher)

Elixir crypto library to encrypt/decrypt arbitrary binaries. It uses
[Erlang Crypto](http://www.erlang.org/doc/man/crypto.html), so it's not big
deal. Mostly a collection of helpers wrapping it.

This library allows us to use a crypted key to validate signed requests, with a
cipher compatible with
[this one](https://gist.github.com/rubencaro/9545060#file-gistfile3-ex).
This way it can be used from Python, Ruby or Elixir apps.

## Use

Just add `{:cipher, github: "rubencaro/cipher"}` to your `mix.exs`.

Basically you use `encrypt/3` and `decrypt/3` to get it. You have to pass them
a key/iv pair previously generated using `generate_key/1` and `generate_iv/1`.

## Sign/validate a URL

Here you use `sign_url/3` and `validate_signed_url/3`.

`sign_url` will add a `signature` parameter to the query string. It's a crypted
hash based on the given path.
`validate_signed_url` must be given an url with the `signature` parameter on the
query string as the last one. It will pop it, and validate it corresponds with
the rest of the URL.

An example of use is [Sequeler](https://github.com/rubencaro/sequeler), and goes
like this:

* Generate the key/iv pair using `generate_key/1` and `generate_iv/1`, usually in
compile-time.
* Get the complete `path` for the request, and validate that it's signed with
the same key/iv with a call to `validate_signed_url/3`

```elixir
    defmodule Sequeler.Plug do
      alias Cipher, as: C

      # ...

      # handy to have them around
      @k Application.get_env(:sequeler, :key_phrase) |> C.generate_key
      @i Application.get_env(:sequeler, :iv_phrase) |> C.generate_iv

      # ...

      get "/query" do
        path = "/query?" <> conn.query_string
        valid? = C.validate_signed_url(path, @k, @i)

        conn = case valid? do
          true -> conn |> fetch_params |> Sequeler.Controller.query
          false -> resp(conn, 401, "Unauthorized")
        end

        send_resp conn
      end

      # ...

    end
```

## TODOs

* Add to travis
* Add to hex
* Sign POST/PUT body
* Improve README

