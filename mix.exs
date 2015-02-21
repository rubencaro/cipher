defmodule Cipher.Mixfile do
  use Mix.Project

  def project do
    [app: :cipher,
     version: "0.1.0",
     elixir: "~> 1.0",
     package: package,
     description: """
        Elixir crypto library to encrypt/decrypt arbitrary binaries. It uses
        Erlang Crypto, so it's not big deal. Mostly a collection of helpers
        wrapping it. It allows to use a crypted key to validate signed requests.
        The exact same cipher is implemented for Python, Ruby and Elixir, so it
        can be used to integrate apps from different languages.
      """]
  end

  defp package do
    [contributors: ["Rubén Caro"],
     licenses: ["MIT"],
     links: %{github: "https://github.com/rubencaro/cipher",
              other_languages: "https://gist.github.com/rubencaro/9545060"}]
  end

end
