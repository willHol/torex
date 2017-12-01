defmodule Torex.Socket do
  use GenServer

  require Logger

  def start_link(_) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    Process.flag(:trap_exit, true)
    %{ControlPort: port} = Application.get_env(:torex, :args)

    {:ok, socket} = :gen_tcp.connect('localhost', port,
                      [:binary, packet: :line, active: false, keepalive: true])

    :gen_tcp.controlling_process(socket, self())

    {:ok, socket}
  end

  def send(msg) do
    GenServer.call(__MODULE__, {:send, format_msg(msg)})
  end

  def recv() do
    GenServer.call(__MODULE__, {:recv, 0})
  end

  def format_msg(msg) do
    normal = String.replace(msg, "\r\n", "\n")

    if normal =~ "\n" do
      "+#{String.replace(normal, "\n", "\r\n")}\r\n.\r\n"
    else
      "#{normal}\r\n"
    end
  end

  def handle_call(:socket, _from, socket), do: {:reply, socket, socket}

  def handle_call({:send, packet}, _from, socket) do
    case :gen_tcp.send(socket, packet) do
      :ok ->
        {:reply, :ok, socket}
      {:error, reason} ->
        {:stop, reason, socket}
    end
  end

  def handle_call({:recv, bytes}, _from, socket) do
    case :gen_tcp.recv(socket, bytes) do
      {:ok, data} ->
        {:reply, data, socket}
      {:error, reason} ->
        {:stop, reason, socket}
    end
  end

  def handle_info({:tcp_closed, _socket}, socket) do
    {:stop, socket}
  end

  def handle_info({:tcp_error, _socket, reason}, socket) do
    Logger.error fn ->
      "Socket error #{inspect reason}: #{inspect socket}"
    end
    {:stop, socket}
  end

  def handle_info({:EXIT, _from, _reason}, socket) do
    {:stop, socket}
  end

  def terminate(_reason, socket) do
    Logger.error fn ->
      "Socket closed: #{inspect socket}"
    end
    :gen_tcp.close(socket)
  end
end