use Mix.Config

config :torex,
  args: %{
    ControlPort: 4000,
    SocksPort: 6000
  },
  password: "password",
  cookie_path: "/var/lib/tor/control_auth_cookie"

config :logger, :console,
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
