defmodule Torex.Controller.Socket do
  @moduledoc """
  Represents a controlling link to an active Tor process
  """
  use GenServer

  require Logger

  def start_link(_) do
    # Queue stores received messages from the socket
    queue = :queue.new()

    GenServer.start_link(__MODULE__, queue, name: __MODULE__)
  end

  def init(queue) do
    Process.flag(:trap_exit, true)
    %{ControlPort: port} = Application.get_env(:torex, :args)

    {:ok, socket} = :gen_tcp.connect('localhost', port,
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