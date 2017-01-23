defmodule Cipher.ValidatePlug do
  import Plug.Conn

  @moduledoc """
  Plug that uses Cipher to validate signatures and halt with 401 when not valid.
  Use like this:

  ```
  # ...
  plug Cipher.ValidatePlug
  # ...
  ```

  Or pass an `error_callback` to be able to do things before halting with 401:
  ```
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
  """

  def init(opts), do: opts

  def call(conn, opts \\ []) do
    url = "#{conn.request_path}?#{conn.query_string}"

    m = conn.method
    validation = cond do
      m in ["POST", "PUT"] ->
        # here body is already parsed by `Plug.Parsers`
        # so we need the signature to be done using `Cipher.sign_url_from_mapped_body`
        Cipher.validate_signed_body(url, conn.body_params)
      true ->
        Cipher.validate_signed_url(url)
    end

    case validation do
      {:ok, _} -> conn

      {:error, error} ->
        # call user fun if given
        if opts[:error_callback], do: opts[:error_callback].(conn, error)

        if opts[:test_mode] do
          conn
        else
          conn
          |> send_resp(401, "unauthorized")
          |> halt
        end
    end
  end

end
