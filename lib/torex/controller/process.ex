defmodule Torex.Controller.Process do
  use GenServer

  require Logger

  @logger_regex ~r(\w{3} \w{2} \w{2}:\w{2}:\w{2}.\w{3} \[\w+\] )
  @permissions 0o700

  def start_link(tor_args) do
    GenServer.start_link(__MODULE__, tor_args, name: __MODULE__)
  end

  def init(tor_args) do
    Process.flag(:trap_exit, true)

    # Shows up in the logs as tor_log=false
    Logger.metadata(tor_log: false)

    executable = Application.get_env(:torex, :executable, System.find_executable("tor"))

    case Application.get_env(:torex, :args) do
      %{ControlSocket: path} when not is_nil(path) ->
        :ok = create_socket_file(path)
      _ ->
        :ok
    end

    unless executable do
      raise File.Error, message: "Unable to locate tor executable, please"
                              <> "ensure that Tor is in your PATH."
    end

    port =
      if parent = Application.get_env(:torex, :parent_executable) do
        Port.open({:spawn_executable, parent},
                  [:binary, :exit_status, :hide, :use_stdio, :stderr_to_stdout,
                   args: [executable | tor_args]])
      else
        Port.open({:spawn_executable, executable},
                  [:binary, :exit_status, :hide, :use_stdio, :stderr_to_stdout,
                   args: tor_args])
      end

    # Links the port to the current process
    true = Port.connect(port, self())

    # Read from stdin to determine startup success
    case handle_bootstrap(port) do
      :ok -> {:ok, port}
      :error -> {:stop, :bootstrap_failed}
    end
  end

  def handle_info({_port, {:data, line}}, port) do
    translate_logs(line)
    {:noreply, port}
  end

  def handle_info({_port, {:exit_status, code}}, port) do
    Logger.error fn ->
      "Tor exited with status: #{code}"
    end
    {:stop, :stop, port}
  end

  # Trapped exit handler
  def handle_info({:EXIT, _from, _reason}, state) do
    {:stop, :exit, state}
  end

  def terminate(_reason, port) do
    Logger.error fn ->
      "Process closed: #{inspect port}"
    end

    case Application.get_env(:torex, :args) do
      %{ControlSocket: path} when not is_nil(path) ->
        destroy_socket_file(path)
    end

    case Port.info(port) do
      nil -> true
      info -> kill_port(info)
    end

    Port.close(port)

    {:stop, :closed}
  end

  defp kill_port(info) do
    os_pid = Keyword.get(info, :os_pid)
    :os.cmd('kill #{os_pid}')
  end

  defp translate_logs(lines) do
    lines
    |> String.split("\n")
    |> Enum.each(&translate_log/1)
  end

  defp translate_log(line) do
    stripped_line =
      line
      |> String.replace(@logger_regex, "")
      |> String.replace_trailing("\n", "")

    Logger.metadata(tor_log: true)

    cond do
      line =~ "[debug]" ->
        Logger.debug fn  ->
          stripped_line
        end
      line =~ "[info]" ->
        Logger.info fn  ->
          stripped_line
        end
      line =~ "[notice]" ->
        Logger.info fn  ->
          stripped_line
        end
      line =~ "[warn]" ->
        Logger.warn fn  ->
          stripped_line
        end
      line =~ "[err]" ->
        Logger.error fn  ->
          stripped_line
        end
      true ->
        nil
    end

    Logger.metadata(tor_log: false)
  end

  defp handle_bootstrap(port) do
    receive do
      {^port, {:data, line}} ->
        translate_logs(line)

        cond do
          line =~ "Bootstrapped 100%: Done" ->
            :ok
          line =~ "Bootstrapped" ->
            handle_bootstrap(port)
          line =~ "[warn] Could not bind" || line =~ "[err]" ->
            :error
          true ->
            handle_bootstrap(port)
        end
      {^port, {:exit_status, _code}} ->
        :error
    end
  end

  defp create_socket_file(path) do
    if not File.exists?(path) do
      with :ok <- File.mkdir_p(Path.dirname(path)),
           :ok <- File.write(path, <<>>),
           :ok <- File.chmod(Path.dirname(path), @permissions)
           do
             :ok
           end
    else
      :ok
    end
  end

  defp destroy_socket_file(path) do
    File.rm(path)
  end
end