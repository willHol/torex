defmodule TorexTest do
  use ExUnit.Case
  doctest Torex

  test "greets the world" do
    assert Torex.hello() == :world
  end
end
