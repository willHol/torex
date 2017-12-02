defmodule Torex.Controller.Supervisor do
  use Supervisor

  alias Torex.Controller.{Process, Socket}

  def start_link(_) do
    Supervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    # System env variables take precedence over application variables
    tor_args = Application.get_env(:torex, :args, %{}) |> transform_args()

    children = [
      {Process, tor_args},
      Socket
    ]

    Supervisor.init(children, strategy: :one_for_one, shutdown: 1500,
                                              max_restarts: 3, max_seconds: 90)
  end

  defp transform_args(args) do
    args
    |> Enum.map(fn {k, v} ->
         {"--" <> String.downcase(to_string(k)), String.downcase(to_string(v))}
       end)
    |> Enum.into(%{})
  end
end