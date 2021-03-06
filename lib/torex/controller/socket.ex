defmodule Torex.Controller.ProtocolError do
  defexception [:message]
end

defmodule Torex.Controller.AuthenticationError do
  defexception [:message]
end

defmodule Torex.Controller.ConfigurationError do
  defexception [:message]
end

defmodule Torex.Controller.Socket do
  @moduledoc """
  Represents a controlling link to an active Tor process
  """
  use GenServer
  require Logger

  alias Torex.Controller.ConfigurationError

  def start_link(_) do
    # Queue stores received messages from the socket
    queue = :queue.new()

    GenServer.start_link(__MODULE__, queue, name: __MODULE__)
  end

  def init(queue) do
    Process.flag(:trap_exit, true)

    # Shows up in the logs as tor_log=false
    Logger.metadata(tor_log: false)

    {address, port} =
      case Application.get_env(:torex, :args) do
        %{ControlSocket: file} when not is_nil(file) ->
          # Set up a Unix Domain Socket
          {{:local, file}, 0}
        %{ControlPort: port} when not is_nil(port) ->
          {'127.0.0.1', port}
        _else ->
          raise ConfigurationError, message: "Neither ControlPort nor"
                                          <> "ControlSocket is specified in the"
                                          <> "application configuration."
      end

    {:ok, socket} = :gen_tcp.connect(address, port,
                      [:binary, packet: :line, active: true, keepalive: true])

    :gen_tcp.controlling_process(socket, self())

    {:ok, {socket, queue}}
  end

  def send(msg) do
    GenServer.call(__MODULE__, {:send, format_msg(msg)})
  end

  def send_and_wait(msg, timeout \\ 500) do
    GenServer.call(__MODULE__, :passive)
    GenServer.call(__MODULE__, {:send, format_msg(msg)})
    GenServer.call(__MODULE__, {:wait, timeout}, :infinity)
    GenServer.call(__MODULE__, :active)
  end

  def send_and_recv(msg, timeout \\ 750) do
    send_and_wait(msg, timeout)
    recv_all()
  end

  def recv() do
    GenServer.call(__MODULE__, :recv)
  end

  def recv_all(acc \\ []) do
    case recv() do
      nil -> Enum.reverse(acc)
      x -> recv_all([x | acc])
    end
  end

  def format_msg(msg) do
    normal = String.replace(msg, "\r\n", "\n")

    if normal =~ "\n" do
      "+#{String.replace(normal, "\n", "\r\n")}\r\n.\r\n"
    else
      "#{normal}\r\n"
    end
  end

  def unformat_msg(msg) do
    msg
    |> String.replace_suffix("\r\n.\r\n", "")
    |> String.replace_suffix("\r\n", "")
  end

  def handle_call(:passive, _from, {socket, _queue} = state) do
    case :inet.setopts(socket, [{:active, false}]) do
      :ok -> {:reply, :ok, state}
      {:error, _} -> {:reply, :error, state}
    end
  end

  def handle_call(:active, _from, {socket, _queue} = state) do
    case :inet.setopts(socket, [{:active, true}]) do
      :ok -> {:reply, :ok, state}
      {:error, _} -> {:reply, :error, state}
    end
  end

  def handle_call({:wait, timeout}, _from, {socket, queue} = state) do
    queue =
      case :gen_tcp.recv(socket, 0, timeout) do
        {:ok, data} -> :queue.in(unformat_msg(data), queue)
        {:error, _reason} -> queue
      end

    {:reply, :ok, {socket, queue}}
  end

  def handle_call(:socket, _from, {socket, _queue}), do: {:reply, socket, socket}

  def handle_call({:send, packet}, _from, {socket, _queue} = state) do
    case :gen_tcp.send(socket, packet) do
      :ok ->
        {:reply, :ok, state}
      {:error, reason} ->
        {:stop, reason, state}
    end
  end

  # Dequeues received packets
  def handle_call(:recv, _from, {socket, queue}) do
    case :queue.out(queue) do
      {{:value, item}, queue} ->
        {:reply, item, {socket, queue}}
      {:empty, queue} ->
        {:reply, nil, {socket, queue}}
    end
  end

  # Socket messages
  def handle_info({:tcp, _socket, data}, {socket, queue}) do
    {:noreply, {socket, :queue.in(unformat_msg(data), queue)}}
  end

  def handle_info({:tcp_closed, _socket}, state) do
    {:stop, :tcp_closed, state}
  end

  def handle_info({:tcp_error, _socket, reason}, {socket, _queue} = state) do
    Logger.error fn ->
      "Socket error #{inspect reason}: #{inspect socket}"
    end
    {:stop, :tcp_error, state}
  end

  # Trapped exit handler
  def handle_info({:EXIT, _from, _reason}, state) do
    {:stop, :exit, state}
  end

  def terminate(_reason, {socket, _queue}) do
    Logger.error fn ->
      "Socket closed: #{inspect socket}"
    end
    :gen_tcp.close(socket)
  end
end