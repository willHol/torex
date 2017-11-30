defmodule Torex.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    children = [
      Torex.Process.Supervisor
    ]

    opts = [strategy: :one_for_one, name: Torex.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
