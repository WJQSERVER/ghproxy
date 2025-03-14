package config

import (
	"github.com/BurntSushi/toml"
)

type Config struct {
	Server    ServerConfig
	Httpc     HttpcConfig
	GitClone  GitCloneConfig
	Pages     PagesConfig
	Log       LogConfig
	Auth      AuthConfig
	Blacklist BlacklistConfig
	Whitelist WhitelistConfig
	RateLimit RateLimitConfig
	Outbound  OutboundConfig
}

/*
[server]
host = "0.0.0.0"  # 监听地址
port = 8080  # 监听端口
sizeLimit = 125 # 125MB
H2C = true # 是否开启H2C传输
enableH2C = "on"  # 是否开启H2C传输(latest和dev版本请开启) on/off (2.4.0弃用)
*/

type ServerConfig struct {
	Port      int    `toml:"port"`
	Host      string `toml:"host"`
	SizeLimit int    `toml:"sizeLimit"`
	H2C       bool   `toml:"H2C"`
	Cors      string `toml:"cors"`
	EnableH2C string `toml:"enableH2C"`
	Debug     bool   `toml:"debug"`
}

/*
[httpc]
mode = "auto" # "auto" or "advanced"
maxIdleConns = 100 # only for advanced mode
maxIdleConnsPerHost = 60 # only for advanced mode
maxConnsPerHost = 0 # only for advanced mode
*/
type HttpcConfig struct {
	Mode                string `toml:"mode"`
	MaxIdleConns        int    `toml:"maxIdleConns"`
	MaxIdleConnsPerHost int    `toml:"maxIdleConnsPerHost"`
	MaxConnsPerHost     int    `toml:"maxConnsPerHost"`
}

/*
[gitclone]
mode = "bypass" # bypass / cache
smartGitAddr = ":8080"
ForceH2C = true
*/
type GitCloneConfig struct {
	Mode         string `toml:"mode"`
	SmartGitAddr string `toml:"smartGitAddr"`
	ForceH2C     bool   `toml:"ForceH2C"`
}

/*
[pages]
mode = "internal" # "internal" or "external"
enabled = false
theme = "bootstrap" # "bootstrap" or "nebula"
staticDir = "/data/www"
*/
type PagesConfig struct {
	Mode      string `toml:"mode"`
	Enabled   bool   `toml:"enabled"`
	Theme     string `toml:"theme"`
	StaticDir string `toml:"staticDir"`
}

type LogConfig struct {
	LogFilePath string `toml:"logFilePath"`
	MaxLogSize  int    `toml:"maxLogSize"`
	Level       string `toml:"level"`
}

type AuthConfig struct {
	Enabled     bool   `toml:"enabled"`
	AuthMethod  string `toml:"authMethod"`
	AuthToken   string `toml:"authToken"`
	PassThrough bool   `toml:"passThrough"`
}

type BlacklistConfig struct {
	Enabled       bool   `toml:"enabled"`
	BlacklistFile string `toml:"blacklistFile"`
}

type WhitelistConfig struct {
	Enabled       bool   `toml:"enabled"`
	WhitelistFile string `toml:"whitelistFile"`
}

type RateLimitConfig struct {
	Enabled       bool   `toml:"enabled"`
	RateMethod    string `toml:"rateMethod"`
	RatePerMinute int    `toml:"ratePerMinute"`
	Burst         int    `toml:"burst"`
}

/*
[outbound]
enabled = false
url = "socks5://127.0.0.1:1080" # "http://127.0.0.1:7890"
*/
type OutboundConfig struct {
	Enabled bool   `toml:"enabled"`
	Url     string `toml:"url"`
}

// LoadConfig 从 TOML 配置文件加载配置
func LoadConfig(filePath string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
