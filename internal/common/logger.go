/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package common

import (
	"errors"
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
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
