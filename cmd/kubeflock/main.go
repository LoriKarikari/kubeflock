package main

import (
	"context"
	"os"

	"github.com/LoriKarikari/kubeflock/internal/kubeflock"
)

func main() {
	os.Exit(kubeflock.NewApp(os.Stdin, os.Stdout, os.Stderr).Run(context.Background(), os.Args[1:]))
}
