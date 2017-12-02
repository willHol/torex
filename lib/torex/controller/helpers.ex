defmodule Torex.Controller.Helpers do
  def status(lines) do 
    [code] = Enum.take(lines, -1)
    @status_codes[code]
  end

  def map_from_lines(lines) do
    Enum.reduce(lines, %{}, fn line, map ->
      [tag, info] = String.split(line, " ")
      Map.put(map, tag, info)
    end)
  end

  @doc """
  Decomposes a kv string.

  ## Examples
  """
  def decompose_kv_info(info) do
    Enum.reduce(String.split(info, " "), %{}, fn item, map ->
         [key, values] = String.split(item, "=")
         Map.put(map, key, String.split(values, ","))
    end)
  end
end