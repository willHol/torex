use Mix.Config

config :torex,
  args: %{
    ControlSocket: Path.expand("~/tor_tmp/tor.sock"),
    SocksPort: 5556,
    DataDirectory: Path.expand("~/.tor")
  },
  password: "password",
  executable: System.find_executable("tor")

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
