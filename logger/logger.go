package logger

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
)

type Formatter struct {
	logrus.TextFormatter
}

func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	// this whole mess of dealing with ansi color codes is required if you want the colored output otherwise you will lose colors in the logger levels
	var levelColor int
	switch entry.Level {
	case logrus.DebugLevel, logrus.TraceLevel:
		levelColor = 31 // red
	case logrus.WarnLevel:
		levelColor = 33 // yellow
	case logrus.InfoLevel:
		levelColor = 36 // blue
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = 31 // red
	default:
		levelColor = 36 // blue
	}
	//msg := strings.Trim(entry.Message, "[]")
	return []byte(fmt.Sprintf("\x1b[%dm%s\x1b[0m\n", levelColor, entry.Message)), nil
}

var logger = logrus.Logger{
	Out:       os.Stdout,
	Level:     logrus.InfoLevel,
	Formatter: &Formatter{},
}

func Error(msg string) {
	logger.Error(msg)
}

func Info(msg string) {
	logger.Info(msg)
}

func Warn(msg string) {
	logger.Warning(msg)
}

func Fatal(msg string) {
	logger.Fatal(msg)
}

func Println(msg string) {
	fmt.Println(msg)
}
