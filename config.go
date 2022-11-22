package main

type Config struct {
	Credentials map[string]Credential
}

type Credential struct {
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
}
