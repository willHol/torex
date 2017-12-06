use Mix.Config

config :torex,
  args: %{
    ControlSocket: Path.expand("~/tor_tmp/tor.sock"),
    SocksPort: 2000
  },
  password: "password",
  executable: System.find_executable("tor"),
  parent_executable: System.find_executable("firejail")

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
