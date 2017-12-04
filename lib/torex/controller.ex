defmodule Torex.Controller do
  @moduledoc """
  The controller context. Maintains a tor process and authenticated controller
  socket.
  """
  use GenServer
  require Logger

  def start_link(_) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    # Shows up in the logs as tor_log=false
    Logger.metadata(tor_log: false)

    # Supervise the process and socket
    Torex.Controller.Supervisor.start_link([])

    # Authenticate the socket
    {:ok, method} = Torex.authenticate()

    Logger.info fn  ->
      "Control connection successfully authenticated via #{method} method"
    end

    {:ok, []}
  end
end