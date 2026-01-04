package config

import "os"

func Getenv(key, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		val = defaultValue
	}

	return val
}
