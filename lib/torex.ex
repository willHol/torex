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
    "515 Bad authentication." => :bad_auth,
    "514 Authentication required." => :auth_required,
    "552 Unrecognized option." => :unrecognized_opt,
    "552 unknown configuration keyword." => :unrecognized_keyword,
    "513 syntax error in configuration values." => :syntax_error,
    "553 impossible configuration setting." => :impossible_config,
    "552 Unrecognized event." => :unrecognised_event,
    "551 Unable to write configuration to disk." => :unable_to_write_config,
    "552 Unrecognized signal." => :unrecognised_signal,
    "512 syntax error in command argument." => :syntax_error
  }

  @spec protocol_info() :: %{status: atom(), auth_methods: [String.t()],
                                                            version: String.t()}
  def protocol_info() do
    lines = Socket.send_and_recv("PROTOCOLINFO #{@version}")

    unless status(lines) === :success do
      raise ProtocolError, message: "Incorrect status code"
    end

    map = map_from_lines(lines)
    methods = unformat_kv(map["250-AUTH"])["METHODS"]
    [version] = unformat_kv(map["250-VERSION"])["Tor"]

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
        "SAFECOOKIE" in methods and cookie_path != nil ->
          {authenticate_safecookie(cookie_path), "SAFECOOKIE"}
        "HASHEDPASSWORD" in methods and password != nil ->
          {authenticate_hashed_password(password), "HASHEDPASSWORD"}
        "COOKIE" in methods and cookie_path != nil ->
          {authenticate_cookie(cookie_path), "COOKIE"}
        "NULL" in methods ->
          {authenticate_null(), "NULL"}
        true ->
          raise AuthenticationError, message:
            "Unsupported authentication method. You may need to modify your"
            <> " torrc to enable this."
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

    lines = Socket.recv_all()

    if success?(lines) do
      map = unformat_kv(lines)

      [server_hash] = map["SERVERHASH"]
      [server_nonce] = map["SERVERNONCE"]

      %{
        server_hash: server_hash,
        server_nonce: server_nonce
      }
    else
      raise AuthenticationError, message: "Authentication failed: #{status(lines)}"
    end
  end

  @doc """
  Changes the value of one or more configuration variables.
  """
  @spec set_conf([{atom() | String.t(), any()} | atom() | String.t()]) ::
                                                        :ok | {:error, atom()}
  def set_conf(keywords) do
    lines = Socket.send_and_recv("SETCONF #{format_kv(keywords)}")

    if success?(lines) do
      :ok
    else
      {:error, status(lines)}
    end
  end

  @doc """
  Removes all settings for a given configuration option, assign the default
  value, then assign the provided string. This is defined in the spec as a plain
  unquoted string, so as such it must be free of spaces.
  """
  @spec reset_conf([{atom() | String.t(), any()} | atom() | String.t()]) ::
                                                        :ok | {:error, atom()}
  def reset_conf(keywords) do
    lines = Socket.send_and_recv("RESETCONF #{format_kv(keywords)}")

    if success?(lines) do
      :ok
    else
      {:error, status(lines)}
    end
  end

  @doc """
  Requests the value of the configuration variable(s). There is a special case
  for HiddenServiceDir, HiddenServicePort, HiddenServiceVersion, and
  HiddenserviceAuthorizeClient options which require the inclusion of the
  HiddenServiceOptions keyword. Value is the atom :default in the case of 
  defaults.
  """
  @spec get_conf([atom() | String.t()]) ::
            {:ok, %{required(atom()) => [String.t()]}} | {:error, any()}
  def get_conf(keys) do
    lines = Socket.send_and_recv("GETCONF #{format_keys(keys)}")

    if success?(lines) do
      {:ok, unformat_kv(lines, "250")}
    else
      {:error, status(lines)}
    end
  end

  @doc """
  Requests that the server notify the client of events. Any events *not* in the
  event_codes list are turned off; thus, sending set_events() with an empty
  list turns off all event reporting. If the flag string extended? = true,
  Tor may provide extra information with events for this connection.
  """
  @spec set_events([String.t() | atom()], boolean()) :: :ok | {:error, any()}
  def set_events(event_codes, extended? \\ false) do
    msg =
      if extended? do
        "SETEVENTS EXTENDED #{format_kv(event_codes)}"
      else
        "SETEVENTS #{format_kv(event_codes)}"
      end

      lines = Socket.send_and_recv(msg)

      if success?(lines) do
        :ok
      else
        {:error, status(lines)}
      end
  end

  @doc """
  Instructs the server to write out its config options into its torrc.
  """
  @spec save_conf(boolean()) :: :ok | {:error, any()}
  def save_conf(force? \\ false) do
    msg =
      if force? do
        "SAVECONF FORCE"
      else
        "SAVECONF"
      end

      lines = Socket.send_and_recv(msg)

      if success?(lines) do
        :ok
      else
        {:error, status(lines)}
      end
  end

  @doc """
  Sent from the client to the server.

  The meanings of the signals are:

    * `:reload`        - Reload: reload config items
    * `:shutdown`      - Controlled shutdown: if server is an OP, exit immediately.
                         If it's an OR, close listeners and exit after
                         ShutdownWaitLength seconds.
    * `:dump`          - Dump stats: log information about open connections and
                         circuits.
    * `:debug`         - Debug: switch all open logs to loglevel debug.
    * `:halt`          - Immediate shutdown: clean up and exit now.
    * `:cleardnscache` - Forget the client-side cached IPs for all hostnames.
    * `:newnym`        - Switch to clean circuits, so new application requests
                         don't share any circuits with old ones.  Also clears
                         the client-side DNS cache.  (Tor MAY rate-limit its
                         response to this signal.)
    * `:heartbeat`     - Make Tor dump an unscheduled Heartbeat message to log.

    Note that not all of these signals have POSIX signal equivalents:

    RELOAD: HUP
    SHUTDOWN: INT
    HALT: TERM
    DUMP: USR1
    DEBUG: USR2
  """
  @spec signal(:atom | String.t()) :: :ok | {:error, any()}
  def signal(type) do
    lines = Socket.send_and_recv("SIGNAL #{type}")

    if success?(lines) do
      :ok
    else
      {:error, status(lines)}
    end
  end

  @doc """
  The first address in each pair is an "original" address; the second is a
  "replacement" address.
  """
  @spec map_address(keyword()) :: :ok | {:error, any()}
  def map_address(keywords) do
    lines = Socket.send_and_recv("MAPADDRESS #{format_kv(keywords)}")

    if success?(lines) do
      :ok
    else
      {:error, status(lines)}
    end
  end

  @doc """
  Unlike get_conf(), this message is used for data that are not stored in the
  Tor configuration file, and that may be longer than a single line.
  """
  @spec get_info([atom() | String.t()]) :: {:ok, map()} | {:error, any()}
  def get_info(keys) do
    lines = Socket.send_and_recv("GETINFO #{format_kv(keys)}")

    if success?(lines) do
      {:ok, unformat_kv(lines, "250")}
    else
      {:error, status(lines)}
    end
  end

  # Produces a map from a list of strings with any of the following formats:
  #
  #  ["250-k1=v1",
  #  "250 k2=v2",
  #  "250-k3=v3,v4",
  #  "250 k4=v5,v6",
  #  "250 k5",
  #  "250-k6"]
  #
  #  Values can be quoted or unquotedThe returned map would have the following structure:
  #
  #  %{
  #    "k1" => [v1],
  #    k2: [v2],
  #    k3: [v3, v4],
  #    k4: [v5, v6],
  #    k5: nil,
  #    k6: nil
  #  }
  #
  # This function is far too complex, please help :'(
  #
  @doc false
  def unformat_kv(lines, _prefix \\ "")
  def unformat_kv([], _prefix), do: %{}
  def unformat_kv(lines, prefix) do
    lines = strip_ok_status(lines)

    try do
      Enum.reduce(lines, %{}, fn line, map ->
        if line =~ ~r(^#{prefix}\+) do
          # Multiline response
          key =
            line
            |> String.replace(~r(^#{prefix}\+), "")
            |> String.replace_trailing("=", "")

          # We need to break out of this reduce to try again with ramaining lines
          throw {map, key}
        else
          kv =
            if prefix !== "" do
              cond do
                line =~ ~r(^#{prefix} ) ->
                  String.replace(line, ~r(^#{prefix} ), "")
                line =~ ~r(^#{prefix}-) ->
                  String.replace(line, ~r(^#{prefix}-), "")
                true->
                  ""
              end
            else
              line
            end

          cond do
            kv === "" ->
              map
            kv =~ "=" ->
              [k, values_string] = String.split(kv, "=")

              values_mapper = fn value ->
                cond do
                  value =~ ~r(^".*"$) ->
                    # Handles quoted values
                    value
                    |> String.replace_leading(~S("), "")
                    |> String.replace_trailing(~S("), "")
                  true ->
                    value
                end
              end

              values_list =
                values_string
                |> String.split(",")
                |> Enum.map(values_mapper)

              # Update for co-occurences of the same key
              map = Map.update(map, k, values_list, &(&1 ++ values_list))
            true ->
              Map.put(map, kv, nil)
          end
        end
      end)
    catch
      {map_so_far, key} ->
        # Multiline response
        {value, remaining_lines} = unformat_multiline(lines, key, prefix)

        map_so_far = Map.update(map_so_far, key, [value], &(&1 ++ [value]))

        Map.merge(map_so_far, unformat_kv(remaining_lines, prefix), fn _k, v1, v2 ->
          v1 ++ v2
        end)
    end  
  end

  defp unformat_multiline(lines, key, prefix) do
    lines_dropped_before_key =
      Enum.drop_while(lines, fn line ->
        !(line =~ ~r(^#{prefix}\+#{key}=))
      end)

    {concated_string, multilines} =
      Enum.reduce_while(lines_dropped_before_key, {"", []}, fn line, {acc, multiline} ->
        if line == "." do
          {:halt, {acc, [line | multiline]}}
        else
          {:cont, {acc <> line <> "\n", [line | multiline]}}
        end
      end)

      {concated_string, lines_dropped_before_key -- multilines}
  end

  def format_kv(keywords) do
    mapper = fn kv ->
      case kv do
        {k, nil} ->
          ~s( #{k})
        {k, v} when is_list(v) ->
          ~s( #{k}="#{Enum.join(v, ",")}")
        {k, v} when is_binary(v) ->
          if v =~ " " do
            ~s( #{k}="#{v}")
          else
            ~s( #{k}=#{v})
          end
        kv ->
          ~s( #{kv})
      end
    end

    keywords
    |> Enum.map(mapper)
    |> Enum.join()
    |> String.slice(1..-1)
  end

  def format_keys(keys) do
    keys
    |> Enum.map(&(" #{&1}"))
    |> Enum.join()
    |> String.slice(1..-1)
  end

  # ========================================= #
  #           Non-protocol Functions          #
  # ========================================= #

  def get_hidden_service_conf() do
    case get_conf(["HiddenServiceOptions"]) do
      {:ok, %{"HiddenServiceOptions" => nil}} ->
        {:ok, %{}}
      {:ok, map} ->
        [target_port, host, port] = unformat_virt_port(unwrap_list(map["HiddenServicePort"]))

        {:ok, %{
          directory: unwrap_list(map["HiddenServiceDir"]),
          port: port,
          target_port: target_port,
          host: host,
          version: unwrap_list(map["HiddenServiceVersion"]),
          authorized_clients: map["HiddenServiceAuthorizeClient"]
        }}
      other -> other
    end
  end

  def set_hidden_service_conf(conf) do
    # Using [] as it returns nil - . notation causes error
    transformed_map =
      %{
        "HiddenServiceDir" => conf[:directory],
        "HiddenServicePort" => format_virt_port(conf),
        "HiddenServiceVersion" => conf[:version],
        "HiddenserviceAuthorizeClient" => conf[:authorized_clients]
      }

    set_conf(transformed_map)   
  end

  def create_hidden_service(directory, port, target_port, host \\ "127.0.0.1", client_names \\ []) do
    args_config = %{
      directory: directory,
      port: port,
      target_port: target_port,
      host: host,
      authorized_clients: client_names
    }

    with {:ok, current_conf} <- get_hidden_service_conf(),
         new_conf <- Map.merge(current_conf, args_config),
         :ok <- set_hidden_service_conf(new_conf)
    do
      hostname =
        case read_hostname("#{directory}/hostname") do
          {:ok, hostname} -> hostname
          {:error, _reason} -> nil
        end

      host_for_clients = 
        if client_names !== [] do
          hostnames_for_clients(hostname)
        else
          nil    
        end
      

      %{
        directory: new_conf[:directory],
        hostname: hostname,
        host_for_clients: host_for_clients,
        config: new_conf
      }
    end
  end

  # ========================================= #
  #             Private Functions             #
  # ========================================= #

  def hostnames_for_clients(hostnames) do
    decompose_line = fn line ->
      case String.split(line, " ", trim: true) do
        [hostname, _hash, "#", "client:", client_name] ->
          {client_name, hostname}
      end
    end

    hostnames
    |> String.split("\n", trim: true)
    |> Enum.map(decompose_line)
    |> Enum.into(%{})
  rescue
    _ -> %{}
  end

  defp read_hostname(_path, reason \\ :unknown, tries \\ 3)
  defp read_hostname(_path, reason, 0), do: {:error, reason}
  defp read_hostname(path, _reason, tries) do
    case File.read(path) do
      {:ok, bin} ->
        {:ok, String.trim(bin)}
      {:error, reason} ->
        :ok = :timer.sleep(75)
        read_hostname(path, reason, tries - 1)
    end
  end

  defp unformat_virt_port(virt_port) do
    case String.split(virt_port, ~r([\s, :])) do
      [target_port, host, port] -> [target_port, host, port]
      _ -> [nil, nil, nil]
    end
  end

  defp format_virt_port(conf) do
    target_port = conf[:target_port] || ""
    host = conf[:host] || ""
    port = conf[:port] || ""

    "#{target_port} #{host}:#{port}"
  end

  defp unwrap_list([single_item]) do
    single_item
  end
  defp unwrap_list(multi_item) do
    multi_item
  end

  defp strip_ok_status(lines) do
    [last] = Enum.take(lines, -1)

    if last =~ "250 OK" do
      Enum.slice(lines, 0..-2)
    else
      lines
    end
  end

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
    [last] = Enum.take(lines, -1)
    @status_codes[get_code(lines)] || last
  end

  defp success?(lines) do
    case Enum.take(lines, -1) do
      [line] ->
        line =~ ~r(^250)
      _ ->
        false
    end
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
end
