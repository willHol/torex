use Mix.Config

config :torex,
  args: %{
    ControlPort: 4000
  },
  password: "password",
  cookie_path: "/var/lib/tor/control_auth_cookie"

config :logger, :console,
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
