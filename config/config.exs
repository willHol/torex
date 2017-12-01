use Mix.Config

config :torex,
  args: %{
    ControlPort: 4000
  }

config :logger, :console,
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
