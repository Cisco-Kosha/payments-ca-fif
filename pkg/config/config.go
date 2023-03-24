package config

import (
	"flag"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	serverUrl      string
	consumerId     string
	consumerSecret string
}

func Get() *Config {
	conf := &Config{}
	flag.StringVar(&conf.consumerId, "consumerId", os.Getenv("CONSUMER_ID"), "Application Consumer ID")
	flag.StringVar(&conf.consumerSecret, "consumerSecret", os.Getenv("CONSUMER_SECRET"), "Application Consumer Secret")

	flag.StringVar(&conf.serverUrl, "serverUrl", os.Getenv("SERVER_URL"), "Server Url")

	flag.Parse()

	return conf
}

func (c *Config) GetConsumerIDAndSecret() (string, string) {
	return c.consumerId, c.consumerSecret
}

func (c *Config) GetServerURL() string {
	c.serverUrl = strings.TrimSuffix(c.serverUrl, "/")
	u, _ := url.Parse(c.serverUrl)
	if u.Scheme == "" {
		return "https://" + c.serverUrl
	} else {
		return c.serverUrl
	}
}

func (c *Config) GetServerHost() string {
	c.serverUrl = strings.TrimSuffix(c.serverUrl, "/")
	u, _ := url.Parse(c.serverUrl)
	if u.Scheme == "" {
		return u.Host
	} else {
		return u.Host
	}
}
