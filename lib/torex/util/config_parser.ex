defmodule Torex.Util.ConfigParser do
  @moduledoc """
  Parses a torrc config file.
  """

  def parse(path) do
    parse_kv_line = fn line ->
      [key | value_split] = String.split(line, " ")
      {String.to_atom(key), Enum.join(value_split, " ")}
    end

    File.stream!(path, [], :line)
    |> Stream.filter(fn line -> String.match?(line, ~r([^$,^\n$])) end)
    |> Stream.filter(fn line -> !(String.match?(line, ~r(^#))) end)
    |> Stream.map(fn line -> String.trim_trailing(line, "\n") end)
    |> Stream.map(parse_kv_line)
    |> Enum.into(%{})
  end
end