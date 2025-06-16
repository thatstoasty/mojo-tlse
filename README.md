# mojo-tlse

`tlse` bindings for Mojo.
This library provides bindings for the `tlse` library, which is a TLS implementation in Mojo. It allows you to create secure connections using TLS protocols.

![Mojo Version](https://img.shields.io/badge/Mojo%F0%9F%94%A5-25.4-orange)

## Installation

1. First, you'll need to configure your `mojoproject.toml` file to include my Conda channel. Add `"https://repo.prefix.dev/mojo-community"` to the list of channels.
2. Next, add `mojo-tlse` to your project's dependencies by running `pixi add mojo-tlse`.
3. Finally, run `pixi install` to install in `mojo-tlse` and its dependencies. You should see the `.mojopkg` files in `$CONDA_PREFIX/lib/mojo/`.
