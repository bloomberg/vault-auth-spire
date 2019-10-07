package main

import (
	"errors"
	"github.com/spf13/viper"
)

type Settings struct {
	Log           *LogSettings
	SourceOfTrust *SourceOfTrustSettings
}

type SourceOfTrustSettings struct {
	File *FileSourceOfTrustSettings
}

type FileSourceOfTrustSettings struct {
	domains map[string]string
}

type LogSettings struct {
	Filename   string
	Level      string
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
}

func wrapError(err error) error {
	return errors.New("parse-settings: " + err.Error())
}

func ReadSettings(fromPath string) (*Settings, error) {
	settings := new(Settings)

	// cause we use it a few times
	var err error

	// Load the config from disk at sourcePath
	viper.SetConfigFile(fromPath)
	if err = viper.ReadInConfig(); err != nil {
		return nil, wrapError(err)
	}

	// Read logging settings
	if settings.Log, err = readLogSettings(); err != nil {
		return nil, wrapError(err)
	}

	// Read our source of trust settings
	if settings.SourceOfTrust, err = readSourceOfTrustSettings(); err != nil {
		return nil, wrapError(err)
	}

	return settings, nil
}

func readLogSettings() (*LogSettings, error) {
	// Set defaults for non-reqiured values
	viper.SetDefault("log.level", "INFO")
	viper.SetDefault("log.maxsize", 10)
	viper.SetDefault("log.maxbackups", 10)
	viper.SetDefault("log.maxage", 30)
	viper.SetDefault("log.compress", false)

	// Check for required values
	if !viper.IsSet("log.filename") {
		return nil, errors.New("log.filename is required but not found")
	}

	logSettings := new(LogSettings)
	logSettings.Filename = viper.GetString("log.filename")
	logSettings.Level = viper.GetString("log.level")
	logSettings.MaxSize = viper.GetInt("log.maxsize")
	logSettings.MaxBackups = viper.GetInt("log.maxbackups")
	logSettings.MaxAge = viper.GetInt("log.maxage")
	logSettings.Compress = viper.GetBool("log.compress")

	return logSettings, nil
}

func readSourceOfTrustSettings() (*SourceOfTrustSettings, error) {
	if !viper.IsSet("trustsource.file") && !viper.IsSet("trustsource.spire") {
		return nil, errors.New("Either trustsource.file or trustsource.spire are required but neither found")
	}

	// cause we use it a few times
	var err error

	sourceOfTrust := new(SourceOfTrustSettings)

	if viper.IsSet("trustsource.file") {
		if sourceOfTrust.File, err = readFileSourceOfTrustSettings(); err != nil {
			return nil, err
		}
	}

	// TODO: Add implementation for Spire being the source of trust
	//if(viper.IsSet("trustsource.spire")){
	//	if trustSettings.File, err = readSpireSourceOfTrustSettings(); err != nil {
	//		return nil, err
	//	}
	//}

	return sourceOfTrust, nil
}

func readFileSourceOfTrustSettings() (*FileSourceOfTrustSettings, error) {
	if !viper.IsSet("trustsource.file.domains") {
		return nil, errors.New("trustsource.file.domains is required but not found")
	}

	fileSettings := new(FileSourceOfTrustSettings)
	fileSettings.domains = viper.GetStringMapString("trustsource.file.domains")

	return fileSettings, nil
}
