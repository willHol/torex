defmodule Torex.ProcessSupervisor do
  use Supervisor

  def start_link(_) do
    Supervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    # System env variables take precedence over application variables
    tor_args = Application.get_env(:torex, :args, %{}) |> transform_args()

    Supervisor.init([
      {Torex.Process, tor_args}
    ], strategy: :one_for_one, max_restarts: 500, max_seconds: 120)
  end

  defp transform_args(args) do
    args
    |> Enum.map(fn {k, v} ->
         {"--" <> String.downcase(to_string(k)), String.downcase(to_string(v))}
       end)
    |> Enum.into(%{})
  end
end