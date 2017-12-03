defmodule Torex.Controller.ProtocolError do
  defexception [:message]
end

defmodule Torex.Controller.AuthenticationError do
  defexception [:message]
end

defmodule Torex do
  @moduledoc """
  The main context. Contains all functions for controlling a tor node.
  """

  alias Torex.Controller.{Socket, ProtocolError, AuthenticationError}

  @version 1
  @client_auth_key "Tor safe cookie authentication controller-to-server hash"
  @server_auth_key "Tor safe cookie authentication server-to-controller hash"

  # A map of reply codes
  @status_codes %{
    "250 OK" => :success,
    "515 Bad authentication" => :bad_auth,
    "514 Authentication required" => :auth_required,
    "552 Unrecognized option" => :unrecognized_opt,
    "513 syntax error in configuration values" => :syntax_error,
    "553 impossible configuration setting" => :impossible_config
  }

  @spec protocol_info() :: %{status: atom(), auth_methods: [String.t()],
                                                            version: String.t()}
  def protocol_info() do
    lines = Socket.send_and_recv("PROTOCOLINFO #{@version}")

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

  @doc """
  Authenticates a control connection. Picks from all methods of authentication.
  Order of precedence is SAFECOOKIE, HASHEDPASSWORD, COOKIE and NULL, in
  decreasing order.  All authentication functions raise exceptions if a
  failure occurs.
  """
  @spec authenticate() :: {:ok, String.t()}
  def authenticate() do
    %{auth_methods: methods} = protocol_info()
    password = Application.get_env(:torex, :password)
    cookie_path = Application.get_env(:torex, :cookie_path)

    {msg, method} =
      cond do
        "SAFECOOKIE" in methods ->
          {authenticate_safecookie(cookie_path), "SAFECOOKIE"}
        "HASHEDPASSWORD" in methods and password != nil ->
          {authenticate_hashed_password(password), "HASHEDPASSWORD"}
        "COOKIE" in methods and cookie_path != nil ->
          {authenticate_cookie(cookie_path), "COOKIE"}
        "NULL" in methods ->
          {authenticate_null(), "NULL"}
        true ->
          raise AuthenticationError, message: "Unrecognised authentication method"
      end

      # Default timeout is not long enough
      lines = Socket.send_and_recv(msg, 10000)

      case status(lines) do
        :success -> {:ok, method}
        :bad_auth -> raise AuthenticationError, message: "Authentication failed"
        :auth_required -> authenticate()
        _ -> raise AuthenticationError, message: "Invalid response status: #{status(lines)}"
      end
  end

  @doc """
  Begins the authentication routine for SAFECOOKIE. All authentication functions
  raise exceptions if a failure occurs.
  """
  @spec auth_challenge(integer() | String.t()) :: %{server_hash: String.t(), server_nonce: String.t()}
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

  @spec set_conf([{atom(), any()} | atom()]) :: :ok | {:error, atom()}
  def set_conf(keywords) do
    mapper = fn val ->
      case val do
        {k, v} -> ~s( #{k}="#{v}")
        val -> ~s( #{val})
      end
    end

    kv_string =
      keywords
      |> Enum.map(mapper)
      |> Enum.join()

    msg = "SETCONF" <> kv_string
    lines = Socket.send_and_recv(msg)

    case status(lines) do
      :success -> :ok
      status -> {:error, status}
    end
  end

  # ========================================= #
  #             Private Functions             #
  # ========================================= #

    defp authenticate_safecookie(cookie_path) do
    case File.read(cookie_path) do
      {:ok, bin} ->
        <<nonce::32>> = :crypto.strong_rand_bytes(4)
        # Trimming to account for small nonces
        nonce_bin = trim_bytes(<<nonce::32>>)
       
        %{server_nonce: server_nonce, server_hash: server_hash} = auth_challenge(nonce)

        computed_server_hash = :crypto.hmac(:sha256, @server_auth_key,
                              bin <> nonce_bin <> Base.decode16!(server_nonce))

        unless Base.encode16(computed_server_hash) === server_hash do
          # This indicates that the server does not have access to the same cookie
          raise AuthenticationError, message: "Server provided an invalid hash"
        end
        
        client_hash = :crypto.hmac(:sha256, @client_auth_key,
                              bin <> nonce_bin <> Base.decode16!(server_nonce))


        ~s(authenticate #{Base.encode16(<<client_hash::binary-size(32)>>)})
      {:error, reason} ->
        raise AuthenticationError, message: "Failed to read cookie file: #{inspect reason}"
    end
  end

  defp authenticate_cookie(cookie_path) do
    case File.read(cookie_path) do
      {:ok, bin} ->
        ~s(authenticate "#{bin}")
      {:error, reason} ->
        raise AuthenticationError, message: "Failed to read cookie file: #{inspect reason}"
    end
  end

  defp authenticate_hashed_password(password) do
    ~s(authenticate "#{password}")
  end

  defp authenticate_null() do
    ~s(authenticate)
  end

  def trim_bytes(<<0, rest::binary>>) do
    trim_bytes(rest)
  end
  def trim_bytes(binary), do: binary

  defp dec_to_hex(int, min_length) do
    String.pad_leading("#{:erlang.integer_to_list(int, 16)}", min_length, "0")
  end

  defp status(lines) do 
    @status_codes[get_code(lines)]
  end

  defp get_code(lines) do
    case Enum.take(lines, -1) do
      [code] ->
        if code == "" do
          get_code(Enum.slice(lines, 0..-2))
        else
          code
        end
      _ ->
        nil
    end
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
