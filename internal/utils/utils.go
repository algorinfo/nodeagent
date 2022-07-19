package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func Env(key, defaultValue string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue
	}
	return val
}

func PrintJSON(j interface{}) error {
	var out []byte
	var err error

	out, err = json.Marshal(j)

	if err == nil {
		fmt.Println(string(out))
	}

	return err
}

type ArgList map[string]string

func (l ArgList) String() string {
	data, _ := json.Marshal(l)
	return string(data)
}

func (l ArgList) Set(arg string) error {
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("Invalid argument '%v'.  Must use format 'key=value'. %v", arg, parts)
	}
	l[parts[0]] = parts[1]
	return nil
}
