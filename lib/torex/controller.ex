defmodule Torex.Controller do
  @moduledoc """
  The controller context. Maintains a tor process and authenticated controller
  socket.
  """
  use Supervisor
  require Logger

  def start_link(_) do
    Supervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    # Shows up in the logs as tor_log=false
    Logger.metadata(tor_log: false)

    # System env variables take precedence over application variables
    tor_args = Application.get_env(:torex, :args, %{}) |> transform_args()

    # Supervise the process and socket
    Supervisor.init([
      {Torex.Controller.Process, tor_args},
      Torex.Controller.Socket
    ], strategy: :one_for_all)
  end

  defp transform_args(args) do
    OptionParser.to_argv(args)
  end
end