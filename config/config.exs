use Mix.Config

config :torex,
  args: %{
    ControlSocket: Path.expand("~/tmp/socket.sock"),
    SocksPort: 6000
  },
  password: "password",
  executable: System.find_executable("tor"),
  parent_executable: System.find_executable("firejail")

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
