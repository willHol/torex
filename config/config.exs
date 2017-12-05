use Mix.Config

config :torex,
  args: %{
    ControlSocket: Path.expand("~/tmp/socket"),
    SocksPort: 6000
  },
  password: "password",
  executable: System.find_executable("tor")

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
