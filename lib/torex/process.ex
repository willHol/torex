defmodule Torex.Process do
  use GenServer

  require Logger

  @logger_regex ~r(\w{3} \w{2} \w{2}:\w{2}:\w{2}.\w{3} \[\w+\] )

  def start_link(%{} = args) do
    GenServer.start_link(__MODULE__, args, [])
  end

  def init(args) do
    port = Port.open({:spawn_executable, System.find_executable("tor")},
                     [:binary, :exit_status, :hide, :use_stdio, :stderr_to_stdout,
                     args: ['__OwningControllerProcess',
                            :erlang.list_to_binary(:os.getpid())] ++ flatten_args_map(args)])

    # Links the port to the current and managing process
    true = Port.connect(port, self())

    # Read from stdin to determine startup success
    case handle_bootstrap(port) do
      :ok ->
        {:ok, port}
      :error ->
        terminate(:bootstrap_failed, port)
        {:stop, :bootstrap_failed}
    end
  end

  def handle_info({_port, {:data, line}}, port) do
    translate_logs(line)
    {:noreply, port}
  end

  def terminate(_reason, port) do
    Port.close(port)
  end

  defp flatten_args_map(%{} = map) do
    Enum.flat_map(map, fn {k, v} -> [k, v] end)
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
          line =~ "[warn]" || line =~ "[err]" ->
            :error
          true ->
            handle_bootstrap(port)
        end
    end
  end
end