#!/bin/bash
sed 's/[^[:print:][:space:]]//g' $@
