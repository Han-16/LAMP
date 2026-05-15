package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func LoadDotEnv() error {
	if explicitPath := os.Getenv("MEOW_ENV_FILE"); explicitPath != "" {
		return loadDotEnvFile(explicitPath, true)
	}

	root, err := ProjectRoot()
	if err != nil {
		return err
	}
	if err := loadDotEnvFile(filepath.Join(root, ".env"), false); err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if cwd != root {
		return loadDotEnvFile(filepath.Join(cwd, ".env"), false)
	}
	return nil
}

func ProjectRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return cwd, nil
		}
		dir = parent
	}
}

func OutputDir(envKey, defaultRelativePath string) string {
	value := GetString(envKey, defaultRelativePath)
	if filepath.IsAbs(value) {
		return value
	}

	root, err := ProjectRoot()
	if err != nil {
		return value
	}
	return filepath.Join(root, value)
}

func GetString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func GetInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func GetBool(key string, defaultValue bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return defaultValue
	}

	switch value {
	case "1", "t", "true", "yes", "y", "on":
		return true
	case "0", "f", "false", "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}

func loadDotEnvFile(path string, required bool) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid .env line %d in %s", lineNumber, path)
		}

		key = strings.TrimSpace(key)
		value = cleanValue(strings.TrimSpace(value))
		if key == "" {
			return fmt.Errorf("empty .env key on line %d in %s", lineNumber, path)
		}
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func cleanValue(value string) string {
	if value == "" {
		return value
	}

	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		return strings.Trim(value, `"`)
	}
	if strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`) {
		return strings.Trim(value, `'`)
	}
	if idx := strings.Index(value, "#"); idx >= 0 {
		return strings.TrimSpace(value[:idx])
	}
	return value
}
