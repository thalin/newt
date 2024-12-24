#!/bin/sh

# Sample from https://github.com/traefik/traefik-library-image/blob/5070edb25b03cca6802d75d5037576c840f73fdd/v3.1/alpine/entrypoint.sh

set -e

# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
    set -- newt "$@"
fi

# if our command is a valid newt subcommand, let's invoke it through newt instead
# (this allows for "docker run newt version", etc)
if newt "$1" --help >/dev/null 2>&1
then
    set -- newt "$@"
else
    echo "= '$1' is not a newt command: assuming shell execution." 1>&2
fi

exec "$@"