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
	"github.com/spf13/viper"
)

type Settings struct {
	Log           *LogSettings
	SourceOfTrust *SourceOfTrustSettings
}

type SourceOfTrustSettings struct {
	File  *FileTrustSourceSettings
	Spire *SpireTrustSourceSettings
}

type FileTrustSourceSettings struct {
	Domains map[string][]string
}

type SpireTrustSourceSettings struct {
	SpireEndpoints map[string]string
	CertStorePath  string
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

	if viper.IsSet("trustsource.spire") {
		if sourceOfTrust.Spire, err = readSpireSourceOfTrustSettings(); err != nil {
			return nil, err
		}
	}

	return sourceOfTrust, nil
}

func readFileSourceOfTrustSettings() (*FileTrustSourceSettings, error) {
	if !viper.IsSet("trustsource.file.domains") {
		return nil, errors.New("trustsource.file.domains is required but not found")
	}

	fileSettings := new(FileTrustSourceSettings)
	fileSettings.Domains = viper.GetStringMapStringSlice("trustsource.file.domains")

	return fileSettings, nil
}

func readSpireSourceOfTrustSettings() (*SpireTrustSourceSettings, error) {
	if !viper.IsSet("trustsource.spire.domains") {
		return nil, errors.New("trustsource.spire.domains is required but not found")
	}

	spireSettings := new(SpireTrustSourceSettings)
	spireSettings.SpireEndpoints = viper.GetStringMapString("trustsource.spire.domains")
	viper.SetDefault("trustsource.spire.certLocation", "/tmp/vault-spire-certs.json")
	viper.SetDefault("trustsource.spire.storeEnabled", true)
	spireSettings.CertStorePath = viper.GetString("trustsource.spire.certLocation")
	if !viper.GetBool("trustsource.spire.storeEnabled") {
		spireSettings.CertStorePath = ""
	}

	return spireSettings, nil
}
