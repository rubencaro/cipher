defmodule Cipher.Digest do

  @moduledoc """
    Some digesting helpers
  """

  @doc "Generates a suitable key for encryption based on given `phrase`"
  def generate_key(phrase), do: :crypto.hash(:sha, phrase) |> hexdigest |> String.slice(0,16)

  @doc "Generates a suitable iv for encryption based on given `phrase`"
  def generate_iv(phrase) when byte_size(phrase) < 16, do: raise ArgumentError, message: "ivphrase must be at least 16 bytes long"
  def generate_iv(phrase), do: phrase |> String.slice(0,16)

  @doc "Gets an usable string from a binary crypto hash"
  def hexdigest(binary) do
    :lists.flatten(for b <- :erlang.binary_to_list(binary), do: :io_lib.format("~2.16.0B", [b]))
    |> :string.to_lower
    |> List.to_string
  end

end
