package config

import (
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	Port              string `mapstructure:"port"`
	BackendAPIBaseURL string `mapstructure:"api_base_url"`
	JWTAuthToken      string `mapstructure:"jwt_secret"`
	PoolSize          int    `mapstructure:"pool_size"`
}

func LoadConfig() (*Config, error) {
	viper.SetDefault("port", "8080")
	viper.SetDefault("api_base_url", "http://localhost:8000")

	viper.AutomaticEnv()

	viper.SetConfigName("cfg")
	viper.SetConfigType("yml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("No config file found, using environment variables: %v", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	if config.JWTAuthToken == "" {
		log.Fatal("JWT token is required")
	}

	return &config, nil
}