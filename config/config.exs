use Mix.Config

config :torex,
  args: %{
    ControlPort: 2000,
    SocksPort: 6000
  },
  password: "password"

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
