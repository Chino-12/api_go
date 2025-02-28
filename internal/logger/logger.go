package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

func init() {
	// Configure the format the log
	Log.SetFormatter(&logrus.JSONFormatter{})

	// Configure the output (is os.Stderr)
	Log.SetOutput(os.Stdout)

	// Configure the low level
	Log.SetLevel(logrus.InfoLevel)
}
