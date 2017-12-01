defmodule Torex.Socket do
  use GenServer

  require Logger

  def start_link(_) do
    GenServer.start_link(__MODULE__, :ok)
  end

  def init(:ok) do
    Process.flag(:trap_exit, true)

    %{ControlPort: port} = Application.get_env(:torex, :args)

    {:ok, socket} = :gen_tcp.connect('localhost', port,
                      [:binary, packet: :line, active: false, reuseaddr: true])
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