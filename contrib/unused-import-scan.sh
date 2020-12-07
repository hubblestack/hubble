#!/bin/bash

find hubblestack tests -type f -name \*.py \
    | xargs -r pylint --disable=all --enable=unused-import
