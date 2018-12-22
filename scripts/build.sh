#!/usr/bin/env bash
go test
go build  -o dist/gomozzie.so -buildmode=c-shared .
