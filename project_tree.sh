#!/bin/bash
# A simple script to visualize directory structure
find . -maxdepth 3 -not -path '*/.*' | sed -e "s/[^-][^\/]*\// |/g" -e "s/| /|-\//g"
