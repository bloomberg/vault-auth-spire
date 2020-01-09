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

// Settings is the root set of settings for root plugin
type Settings struct {
	Log           *LogSettings
	SourceOfTrust *SourceOfTrustSettings
}

// SourceOfTrustSettings holds settings for all source of truth providers
type SourceOfTrustSettings struct {
	File  *FileTrustSourceSettings
	Spire *SpireTrustSourceSettings
}

// FileTrustSourceSettings holds a mapping of domains to certificate paths
type FileTrustSourceSettings struct {
	Domains map[string][]string
}

// SpireTrustSourceSettings holds spire endpoint locations and a path to store certs from Spire in
type SpireTrustSourceSettings struct {
	SpireEndpointURLs map[string]string
	LocalBackupPath   string
}

// LogSettings holds relevant logging settings
type LogSettings struct {
	Filename   string
	Level      string
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
}

// ReadSettings reads settings from JSON into config objects using Viper
func ReadSettings(fromPath string) (*Settings, error) {
	settings := new(Settings)

	// cause we use it a few times
	var err error

	// Load the config from disk at sourcePath
	viper.SetConfigFile(fromPath)
	if err = viper.ReadInConfig(); err != nil {
		return nil, err
	}

	// Read logging settings
	if settings.Log, err = readLogSettings(); err != nil {
		return nil, err
	}

	// Read our source of trust settings
	if settings.SourceOfTrust, err = readSourceOfTrustSettings(); err != nil {
		return nil, err
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

	viper.SetDefault("trustsource.spire.backupPath", "/var/run/spire/certs/")
	viper.SetDefault("trustsource.spire.storeEnabled", true)
	spireSettings := &SpireTrustSourceSettings{
		SpireEndpointURLs: viper.GetStringMapString("trustsource.spire.domains"),
		LocalBackupPath:   viper.GetString("trustsource.spire.backupPath"),
	}
	if !viper.GetBool("trustsource.spire.storeEnabled") {
		spireSettings.LocalBackupPath = ""
	}

	return spireSettings, nil
}
