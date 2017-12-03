defmodule Torex.Controller.ProtocolError do
  defexception [:message]
end

defmodule Torex.Controller.AuthenticationError do
  defexception [:message]
end

defmodule Torex.Controller do
  @moduledoc """
  The controller context. Maintains a tor process and authenticated controller
  socket.
  """
  use GenServer
  require Logger

  alias Torex.Controller.{Process, Socket, ProtocolError, AuthenticationError}

  @version 1

  # A map of reply codes
  @status_codes %{
    "250 OK" => :success,
    "515 Bad authentication" => :bad_auth
  }

  def start_link(_) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    # Supervise the process and socket
    Torex.Controller.Supervisor.start_link([])

    # Authenticate the socket
    :ok = authenticate()

    Logger.info fn  ->
      "Control connection successfully authenticated"
    end

    {:ok, []}
  end

  @spec protocol_info() :: %{status: atom(), auth_methods: [String.t()],
                                                            version: String.t()}
  def protocol_info() do
    Socket.send_and_wait("PROTOCOLINFO #{@version}")
    lines = Socket.recv_all()

    unless status(lines) === :success do
      raise ProtocolError, message: "Incorrect status code"
    end

    map = map_from_lines(lines)
    methods = decompose_kv_info(map["250-AUTH"])["METHODS"]
    [version] = decompose_kv_info(map["250-VERSION"])["Tor"]

    %{
      status: :success,
      auth_methods: methods,
      version: version
    }
  end

  def authenticate() do
    %{auth_methods: methods} = protocol_info()
    password = Application.get_env(:torex, :password)
    cookie_path = Application.get_env(:torex, :cookie_path)

    msg =
      cond do
        "NULL" in methods ->
          ~s(authenticate)
        "HASHEDPASSWORD" in methods and password != nil ->
          ~s(authenticate "#{password}")
        "SAFECOOKIE" in methods and false ->
          nil
        "COOKIE" in methods and cookie_path != nil ->
          case File.read(cookie_path) do
            {:ok, bin} ->
              ~s(authenticate "#{bin}")
            {:error, reason} ->
              raise AuthenticationError, message: "Failed to read cookie file: #{inspect reason}"
          end
        true ->
          raise AuthenticationError, message: "Unrecognised authentication method"
      end

      Socket.send_and_wait(msg)
      lines = Socket.recv_all()

      case status(lines) do
        :success -> :ok
        :bad_auth -> raise AuthenticationError, message: "Authentication failed"
      end
  end

  @spec auth_challenge(integer()) :: %{server_hash: String.t(), server_nonce: String.t()}
  def auth_challenge(nonce) do
    if String.valid?(nonce) do
      Socket.send_and_wait(~s(AUTHCHALLENGE SAFECOOKIE "#{nonce}"))
    else
      Socket.send_and_wait(~s(AUTHCHALLENGE SAFECOOKIE #{dec_to_hex(nonce, 2)}))
    end

    [line] = Socket.recv_all()
    ["250", "AUTHCHALLENGE" | keys] = String.split(line, " ")
    map = decompose_kv_info(keys)

    [server_hash] = map["SERVERHASH"]
    [server_nonce] = map["SERVERNONCE"]

    %{
      server_hash: server_hash,
      server_nonce: server_nonce
    }
  end


  # ========================================= #
  #             Private Functions             #
  # ========================================= #

  defp dec_to_hex(int, out_len) do
    hex = "#{:erlang.integer_to_list(int, 16)}"
    
    if String.length(hex) >= out_len do
      String.slice(hex, 0..out_len)
    else
      String.pad_leading(hex, out_len - String.length(hex) + 1, "0")
    end
  end

  defp status(lines) do 
    [code] = Enum.take(lines, -1)
    @status_codes[code]
  end

  defp map_from_lines(lines) do
    Enum.reduce(lines, %{}, fn line, map ->
      [tag | info] = String.split(line, " ")
      Map.put(map, tag, info)
    end)
  end

  defp decompose_kv_info(info) do
    Enum.reduce(info,%{}, fn item, map ->
         [key, values] = String.split(item, "=")
         Map.put(map, key, String.split(values, ","))
    end)
  end
end