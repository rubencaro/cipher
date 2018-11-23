# Deprecated

Cipher is currently being phased out and is no longer under activate maintenence.
We suggest you use an alternative for URL signing and validation such as [JWT](https://jwt.io/) or something else.

For more information on why this decision was taken, feel free to refer to [this issue](https://github.com/rubencaro/cipher/issues/22).

# Cipher

[![Build Status](https://api.travis-ci.org/rubencaro/cipher.svg)](https://travis-ci.org/rubencaro/cipher)
[![Hex Version](http://img.shields.io/hexpm/v/cipher.svg?style=flat)](https://hex.pm/packages/cipher)
[![Hex Version](http://img.shields.io/hexpm/dt/cipher.svg?style=flat)](https://hex.pm/packages/cipher)

Elixir crypto library to encrypt/decrypt arbitrary binaries. It uses [Erlang Crypto](http://www.erlang.org/doc/man/crypto.html), so it's not a big deal. Mostly a collection of helpers wrapping it.

This library allows us to use a crypted key to validate signed requests, with a cipher compatible with [this one](https://gist.github.com/rubencaro/9545060#file-gistfile3-ex). This way it can be used from Python, Ruby or Elixir apps.

`Cipher` is only meant for that. **Not for security**. For applications that need any level of security I would recommend using a good implementation of JWT.

## Use

Just add `{:cipher, ">= 1.4.0"}` to your `mix.exs`.

Then add your keys to `config.exs`, **they are needed to compile `Cipher`**:
```elixir
config :cipher, keyphrase: "testiekeyphraseforcipher",
                ivphrase: "testieivphraseforcipher",
                magic_token: "magictoken"
```

You can provide different keys at runtime by using `Application.put_env/3`.

Then you may use any of the given helpers:

## Encrypt/Decrypt binaries

Now you can use bare `encrypt/1` and `decrypt/1`:
```elixir
"secret"
|> Cipher.encrypt  # "KSHHdx0uyveYGY5PHqLAKw%3D%3D"
|> Cipher.decrypt  # "secret"
```

### Decryption errors

When you decrypt non-valid strings you can get two kinds of errors:

* `{:error, "Could not decode string 'yourstring'..."}` if your string was tampered or wrongly transferred.
* `{:error, "Could not decrypt string 'yourstring'..."}` if your string was encrypted using different keys. Maybe some edge cases of tampering too.

## Cipher/Parse JSON

`cipher/1` and `parse/1`. Just as `encrypt/1` and `decrypt/1` but for JSON.

```elixir
%{"hola": " qué tal ｸｿ"}
|> Cipher.cipher  # "qW0Voj3h4nglx4NPy8aLXVY5ze5V3OBu5IoaQTMUUbU%3D"
|> Cipher.parse  #  {:ok, %{"hola" => " qué tal ｸｿ"}}
```

## Sign/Validate a URL

Here you use `sign_url/2` and `validate_signed_url/1`.

`sign_url` will add a `signature` parameter to the end of the query string. It's a crypted hash based on the given path.

```elixir
"/bla/bla?p1=1&p2=2"
|> Cipher.sign_url  # "/bla/bla?p1=1&p2=2&signature=4B6WOiuD9N39K7p%2BnqNIljGh5F%2F%2BnHRQGZC9ih%2Bh%2BHGZc8Tz0KdRJXC%2B5M%2B8%2BHZ2mAXPh3jQcSRieTq4dGm5Ng%3D%3D"
```

`validate_signed_url` must be given an url with the `signature` parameter on the query string just as `sign_url` returned it. It will pop it, and validate that it corresponds with the rest of the URL.

```elixir
"/bla/bla?p1=1&p2=2&signature=4B6WOiuD9N39K7p%2BnqNIljGh5F%2F%2BnHRQGZC9ih%2Bh%2BHGZc8Tz0KdRJXC%2B5M%2B8%2BHZ2mAXPh3jQcSRieTq4dGm5Ng%3D%3D"
|> Cipher.validate_signed_url  # {:ok, %{"md5" => "86e359da7ab4886f3525ac2b9c5edc5b  613146"}}
```

Any changes to the signed URL `"/bla/bla?p1=1&p2=2"` will return `{:error, reason}` when validated.

```elixir
"/bla/bla?p1=1&p2=3&signature=4B6WOiuD9N39K7p%2BnqNIljGh5F%2F%2BnHRQGZC9ih%2Bh%2BHGZc8Tz0KdRJXC%2B5M%2B8%2BHZ2mAXPh3jQcSRieTq4dGm5Ng%3D%3D"
|> Cipher.validate_signed_url  # {:error, "Checksum did not match given base '/bla/bla?p1=1&p2=3'."}
```

### Denied params

You can choose to sign a URL but then add some parameters to the query string that may not be signed, such as a `cachebuster`.

For that you can use `sign_url/2`, which accepts a payload to be included on the crypted signature. If you add a `deny` list, then any parameter on that list will be rejected.

```elixir
signed = "/bla/bla?p1=1&p2=2" |> Cipher.sign_url(deny: ["p1"])

"#{signed}&cachebuster=123456789" |> Cipher.validate_signed_url
#   {:ok,
#   %{"deny" => ["p1"],
#     "md5" => "86e359da7ab4886f3525ac2b9c5edc5b  837505"}}

"#{signed}&cachebuster=123456789&p1=parm"
|> Cipher.validate_signed_url  # {:error, "Parameter 'p1=parm' is not allowed by given signature. Denials: [\"p1\"]"}

```

### Concealed params

Note you can use `sign_url/2` to pass any data within the signature itself, just as you do with the `deny` list. Any payload will be returned by `validate_signed_url/1`.

```elixir
signed = "/bla/bla?p1=1" |> Cipher.sign_url(mydata: "yes, any data")
signed |> Cipher.validate_signed_url
#  {:ok,
#   %{"md5" => "eacac4224aef3bfabee309ee2f95c1e8  176303",
#     "mydata" => "yes, any data"}}
```

If you want to pass cipher data on your URLs you could also use straight `cipher/1` and `parse/1`.

## Sign/Validate body

The same as signing a complete URL with query string, but for PUT/POST requests, where the signed data is in the body.

Helpers are `sign_url_from_body/2` and `validate_signed_body/1`. They put and validate the signature on the query string, so the body is untouched.

```elixir
url = "/bla/bla"
body = Poison.encode! %{"hola": " qué tal ｸｿ"}
signed = Cipher.sign_url_from_body(url, body, deny: ["cb"])
# "/bla/bla?signature=HdlsREqEP9hJmP94..."
{:ok, _} = "#{signed}" |> Cipher.validate_signed_body(body)
{:error, _} = "#{signed}&cb=123456" |> Cipher.validate_signed_body(body)
assert {:ok, _} = "#{signed}&other=123456" |> Cipher.validate_signed_body(body)
```

### Mapped body

When the body is to be validated after parse time (as in a simple `Plug` pipeline, where body can be read only once, and it is read by `Plug.Parsers`) you should sign it using `sign_url_from_mapped_body/2`, passing the body as a `Map`. Like this:

```elixir
url = "/bla/bla"
raw_body = %{"hola": " qué tal ｸｿ"}
body = raw_body |> Poison.encode! |> Poison.decode!
signed = Cipher.sign_url_from_mapped_body(url, raw_body, deny: ["cb"])
# "/bla/bla?signature=HdlsREqEP9hJmP94..."
{:ok, _} = "#{signed}" |> Cipher.validate_signed_body(body)
{:error, _} = "#{signed}&cb=123456" |> Cipher.validate_signed_body(body)
assert {:ok, _} = "#{signed}&other=123456" |> Cipher.validate_signed_body(body)
```

## Magic Token

This is a master signature. If you put this binary as `signature` on your url, then it will always validate. This is useful for development, debugging, private network use, etc. You put your chosen `magic_token` on your `config.exs` and you are good to go.

```elixir
"/bla?any=thing&signature=mymagictoken"
|> Cipher.validate_signed_url  # {:ok, %{}}
```

## Use with Plug applications

Cipher provides `ValidatePlug`, a plug that uses Cipher to validate signatures and halt with 401 when they are not valid.
Use it as any other plug:

```elixir
plug Cipher.ValidatePlug
```

### Options for `ValidatePlug`

1. `error_callback`
2. `test_mode`

You can pass an `error_callback` that will be called right before sending the 401 response. This callback is meant to let the user do things like logging when validation fails. You should not call `send_resp` or `halt` over the `conn`, as that will already be done by the plug.
```elixir
# ...
plug Cipher.ValidatePlug, error_callback: &MyApp.my_validation_error_logging_callback/2
# ...

def my_validation_error_logging_callback(conn, error) do
  # Do something with the `error` message and the `conn`, just like:
  Logger.info(error)
  # right before the plug halts with 401
end

# ...
```

You can also pass `test_mode` as an option (which is `false` by default).
If set to `true`, it will **not** halt the Plug pipeline and will simply continue.

This can be useful in conjunction with `error_callback` where you just log requests whose validation has failed, but continue anyway.

```elixir
  plug(
    Cipher.ValidatePlug,
    test_mode: true,
    error_callback: &MyApp.my_validation_error_logging_callback/2
  )
```

### Notes

Note that for body signature validations (those required by POST, PUT, etc.) this plug requires that the signature is made using `Cipher.sign_url_from_mapped_body`. This is due to the way `Plug` parses the request body. The body can be read only once, and it is already read by the `Plug.Parsers` plug. By the time it gets to the `ValidatePlug` it has already been parsed to a `Map`, so the signature must have been done over the mapped structure of data instead of the plain text encoded body.


## TODOs

* Add large body signing
* Separate package for `ValidatePlug`

## Changelog

### 1.4.0

* Add the possibility of giving different keys at runtime by using `Application.put_env/3`.

### 1.3.4

* Adhere closer to the PKCS#7 implementation described in RFC 5652 (pull request #16)

### 1.3.3

* Fix incompatibility deciphering previous versions's ciphers

### 1.3.2

* Add links to source on generated docs
* Require ivphrase >= 16 bytes

### 1.3.1

* Support Poison 3.x

### 1.3.0

* Add `test_mode` option to ease plug testing

### 1.2.4

* Improve error messages

### 1.2.3

* Fix some bugs
* Remove Elixir 1.4 warnings

### 1.2.0

* Add denied params, remove ignored ones.

### 1.1.1

* Fix `plug` dependency

### 1.1.0

* Add `ValidatePlug`
* Add mapped body signing

### 1.0.5

* Fix end line character replace on incoming signatures

### 1.0.4

* Fix app name on `env` helper

### 1.0.3

* Fix bug when ignoring multiple params

### 1.0.2

* Fix [#3](https://github.com/rubencaro/cipher/issues/3), [#4](https://github.com/rubencaro/cipher/issues/4)

### 1.0.1

* Fix [#2](https://github.com/rubencaro/cipher/issues/2)

### 1.0.0

* First stable release
