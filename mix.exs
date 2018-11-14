defmodule AESCrypt.Mixfile do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :aes_crypt,
      version: @version,
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "AESCrypt",
      description: description(),
      package: package(),
      docs: docs(),
      source_url: "https://github.com/voltone/aes_crypt"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.19", only: :dev}
    ]
  end

  defp description do
    "Read and write files in AES Crypt format"
  end

  defp package do
    [
      maintainers: ["Bram Verburg"],
      licenses: ["BSD 3-Clause"],
      links: %{"GitHub" => "https://github.com/voltone/aes_crypt"}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end
end
