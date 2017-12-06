use Mix.Config

config :torex,
  args: %{
    ControlSocket: Path.expand("~/tor/control.sock"),
    SocksPort: "unix:#{Path.expand("~/tor/socks.sock")}",
    DataDirectory: Path.expand("~/.tor"),
    CookieAuthentication: 1,
    CookieAuthFile: Path.expand("~/tor/cookie_auth_file")
  },
  password: "password",
  executable: System.find_executable("tor"),
  torrc: "/etc/tor/torrc"

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
