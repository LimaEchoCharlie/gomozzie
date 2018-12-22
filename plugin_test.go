package main

import (
	"fmt"
	"os"
	"testing"
)

func Test_initialiseLoggerFailure(t *testing.T) {
	tests := []struct {
		name, input string
	}{
		{name: "missingFilename", input: destFile},
		{name: "missingFilenameLeadingWhitespace", input: fmt.Sprintf("\t %s", destFile)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := initialiseLogger(tt.input)
			if err == nil {
				t.Fatal("Expected an error")
			}
		})
	}
}

func Test_initialiseLoggerSuccessSimple(t *testing.T) {
	tests := []struct {
		name, input string
	}{
		{name: "empty", input: ""},
		{name: "oddName", input: "boom"},
		{name: "none", input: destNone},
		{name: "stdout", input: destStdout},
		{name: "leadingWhitespace", input: fmt.Sprintf("\t %s", destStdout)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := initialiseLogger(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error %s", err)
			}
		})
	}
}

func Test_initialiseLoggerSuccessFile(t *testing.T) {
	tests := []struct {
		name, format, filename string
	}{
		{name: "toFile", format: destFile + " %s", filename: "tmp_test.log"},
		{name: "toFileOddWhitespace", format: fmt.Sprintf("\t%s    %%s", destFile), filename: "tmp_test.log"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, f, err := initialiseLogger(fmt.Sprintf(tt.format, tt.filename))
			if err != nil {
				t.Fatalf("Unexpected error %s", err)
			}
			if f == nil {
				t.Fatal("Missing file")
			}
			f.Close()
			os.Remove(tt.filename)
		})
	}
}
