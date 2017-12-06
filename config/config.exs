use Mix.Config

config :torex,
  args: %{
    ControlSocket: Path.expand("~/tor_tmp/tor.sock"),
    SocksPort: 9999,
    DataDirectory: Path.expand("~/.tor"),
    CookieAuthentication: 1,
    CookieAuthFile: "/var/lib/tor/control_auth_cookie"
  },
  password: "password",
  executable: System.find_executable("tor")

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
