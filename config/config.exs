use Mix.Config

config :torex,
  args: %{
    ControlPort: 4000
  },
  password: "password",
  cookie_path: "/var/lib/tor/control_auth_cookie"

config :logger, :console,
  format: "\n$time $metadata[$level] $levelpad$message\n",
  metadata: [:tor_log],
  colors: [debug: :cyan, info: :light_magenta, warn: :yellow, error: :red]
