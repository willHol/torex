defmodule Torex.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    # Merges all torrc options into the application env
    torrc_path = Application.get_env(:torex, :torrc)
    application_args = Application.get_env(:torex, :args)
    torrc = Torex.Util.ConfigParser.parse(torrc_path)

    merged_args = Map.merge(torrc, application_args)
    Application.put_env(:torex, :args, merged_args)
    IO.inspect merged_args

    children = [
      Torex.Controller,
      {Task.Supervisor, name: Torex.TaskSupervisor, restart: :temporary}
    ]

    opts = [strategy: :one_for_one, name: Torex.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
