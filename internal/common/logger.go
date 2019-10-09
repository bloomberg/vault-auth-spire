package common

import (
	"errors"
	"go.dev.bloomberg.com/bbgo/go-logrus"
	"go.dev.bloomberg.com/bbgo/go-lumberjack"
	"io/ioutil"
	"os"
	"path/filepath"
)

type pluginFileLogger struct {
	formatter logrus.Formatter
	logger    *lumberjack.Logger
	minLevel  logrus.Level
}

func (h *pluginFileLogger) Levels() []logrus.Level {
	return logrus.AllLevels[:h.minLevel+1]
}

func (h *pluginFileLogger) Fire(e *logrus.Entry) error {
	formatted, err := h.formatter.Format(e)
	if err != nil {
		return err
	}

	_, err = h.logger.Write(formatted)
	return err
}

type utcFormatter struct {
	formatter logrus.Formatter
}

func (u utcFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return u.formatter.Format(e)
}

func InitializeLogger(settings *Settings) error {
	logDirectory := filepath.Dir(settings.Log.Filename)
	if err := os.MkdirAll(logDirectory, 0755); err != nil {
		return errors.New("Unable to create log directory " + logDirectory + " - " + err.Error())
	}

	logger := lumberjack.Logger{
		Filename:   settings.Log.Filename,
		MaxSize:    settings.Log.MaxSize,
		MaxAge:     settings.Log.MaxAge,
		MaxBackups: settings.Log.MaxBackups,
		LocalTime:  false, // omg never use local time
	}

	logLevel, err := logrus.ParseLevel(settings.Log.Level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}

	fileLogger := &pluginFileLogger{
		formatter: utcFormatter{
			formatter: &logrus.TextFormatter{},
		},
		logger:   &logger,
		minLevel: logLevel,
	}

	logrus.AddHook(fileLogger)
	logrus.SetLevel(logLevel)
	logrus.SetOutput(ioutil.Discard)

	return nil
}
