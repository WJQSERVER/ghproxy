package proxy

import (
	"fmt"
	"ghproxy/auth"
	"ghproxy/config"
	"ghproxy/rate"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var re = regexp.MustCompile(`^(http:|https:)?/?/?(.*)`) // 匹配http://或https://开头的路径
/*
var exps = []*regexp.Regexp{
	regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:releases|archive)/.*`),     // 匹配 GitHub Releases 或 Archive 链接
	regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:blob|raw)/.*`),             // 匹配 GitHub Blob 或 Raw 链接
	regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:info|git-).*`),             // 匹配 GitHub Info 或 Git 相关链接 (例如 .gitattributes, .gitignore)
	regexp.MustCompile(`^(?:https?://)?raw\.github(?:usercontent|)\.com/([^/]+)/([^/]+)/.+?/.+`), // 匹配 raw.githubusercontent.com 链接
	regexp.MustCompile(`^(?:https?://)?gist\.github(?:usercontent|)\.com/([^/]+)/.+?/.+`),        // 匹配 gist.githubusercontent.com 链接
	regexp.MustCompile(`^(?:https?://)?api\.github\.com/repos/([^/]+)/([^/]+)/.*`),               // 匹配 api.github.com/repos 链接 (GitHub API)
}
*/

func NoRouteHandler(cfg *config.Config, limiter *rate.RateLimiter, iplimiter *rate.IPRateLimiter, runMode string) gin.HandlerFunc {
	return func(c *gin.Context) {

		// 限制访问频率
		if cfg.RateLimit.Enabled {

			var allowed bool

			switch cfg.RateLimit.RateMethod {
			case "ip":
				allowed = iplimiter.Allow(c.ClientIP())
			case "total":
				allowed = limiter.Allow()
			default:
				logWarning("Invalid RateLimit Method")
				return
			}

			if !allowed {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too Many Requests"})
				logWarning("%s %s %s %s %s 429-TooManyRequests", c.ClientIP(), c.Request.Method, c.Request.URL.RequestURI(), c.Request.Header.Get("User-Agent"), c.Request.Proto)
				return
			}
		}

		//rawPath := strings.TrimPrefix(c.Request.URL.Path, "/") // 去掉前缀/
		rawPath := strings.TrimPrefix(c.Request.URL.RequestURI(), "/") // 去掉前缀/
		matches := re.FindStringSubmatch(rawPath)                      // 匹配路径
		logInfo("Matches: %v", matches)

		// 匹配路径错误处理
		if len(matches) < 3 {
			errMsg := fmt.Sprintf("%s %s %s %s %s Invalid URL", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto)
			logWarning(errMsg)
			c.String(http.StatusForbidden, "Invalid URL Format. Path: %s", rawPath)
			return
		}

		// 制作url
		rawPath = "https://" + matches[2]

		var (
			user    string
			repo    string
			matcher string
		)

		// 匹配 "https://github.com"开头的链接
		if strings.HasPrefix(rawPath, "https://github.com") {
			remainingPath := strings.TrimPrefix(rawPath, "https://github.com")
			if strings.HasPrefix(remainingPath, "/") {
				remainingPath = strings.TrimPrefix(remainingPath, "/")
			}
			// 预期格式/user/repo/more...
			// 取出user和repo和最后部分
			parts := strings.Split(remainingPath, "/")
			if len(parts) <= 2 {
				logWarning("%s %s %s %s %s Invalid URL", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto)
				c.String(http.StatusForbidden, "Invalid URL Format. Path: %s", rawPath)
				return
			}
			user = parts[0]
			repo = parts[1]
			// 匹配 "https://github.com"开头的链接
			if len(parts) >= 3 {
				switch parts[2] {
				case "releases", "archive":
					matcher = "releases"
				case "blob", "raw":
					matcher = "blob"
				case "info", "git-upload-pack":
					matcher = "clone"
				default:
					fmt.Println("Invalid URL: Unknown type")
				}
			}
		}
		// 匹配 "https://raw"开头的链接
		if strings.HasPrefix(rawPath, "https://raw") {
			remainingPath := strings.TrimPrefix(rawPath, "https://")
			parts := strings.Split(remainingPath, "/")
			if len(parts) <= 3 {
				logWarning("%s %s %s %s %s Invalid URL", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto)
				c.String(http.StatusForbidden, "Invalid URL Format. Path: %s", rawPath)
				return
			}
			user = parts[1]
			repo = parts[2]
			matcher = "raw"
		}
		// 匹配 "https://gist"开头的链接
		if strings.HasPrefix(rawPath, "https://gist") {
			remainingPath := strings.TrimPrefix(rawPath, "https://")
			parts := strings.Split(remainingPath, "/")
			if len(parts) <= 3 {
				logWarning("%s %s %s %s %s Invalid URL", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto)
				c.String(http.StatusForbidden, "Invalid URL Format. Path: %s", rawPath)
				return
			}
			user = parts[1]
			matcher = "gist"
		}
		// 匹配 "https://api.github.com/"开头的链接
		if strings.HasPrefix(rawPath, "https://api.github.com/") {
			matcher = "api"
			remainingPath := strings.TrimPrefix(rawPath, "https://api.github.com/")

			parts := strings.Split(remainingPath, "/")
			if parts[0] == "repos" {
				user = parts[1]
				repo = parts[2]
			}
			if parts[0] == "users" {
				user = parts[1]
			}
			if cfg.Auth.AuthMethod != "header" || !cfg.Auth.Enabled {
				c.JSON(http.StatusForbidden, gin.H{"error": "HeaderAuth is not enabled."})
				logError("%s %s %s %s %s HeaderAuth-Error: HeaderAuth is not enabled.", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto)
				return
			}
		}

		username := user
		//username, repo := MatchUserRepo(rawPath, cfg, c, matches) // 匹配用户名和仓库名

		logInfo("%s %s %s %s %s Matched-Username: %s, Matched-Repo: %s", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto, username, repo)
		// dump log 记录详细信息 c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto, full Header
		logDump("%s %s %s %s %s %s", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto, c.Request.Header)
		repouser := fmt.Sprintf("%s/%s", username, repo)

		// 白名单检查
		if cfg.Whitelist.Enabled {
			whitelist := auth.CheckWhitelist(username, repo)
			if !whitelist {
				logErrMsg := fmt.Sprintf("%s %s %s %s %s Whitelist Blocked repo: %s", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto, repouser)
				errMsg := fmt.Sprintf("Whitelist Blocked repo: %s", repouser)
				c.JSON(http.StatusForbidden, gin.H{"error": errMsg})
				logWarning(logErrMsg)
				return
			}
		}

		// 黑名单检查
		if cfg.Blacklist.Enabled {
			blacklist := auth.CheckBlacklist(username, repo)
			if blacklist {
				logErrMsg := fmt.Sprintf("%s %s %s %s %s Blacklist Blocked repo: %s", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto, repouser)
				errMsg := fmt.Sprintf("Blacklist Blocked repo: %s", repouser)
				c.JSON(http.StatusForbidden, gin.H{"error": errMsg})
				logWarning(logErrMsg)
				return
			}
		}

		/*
			matches = CheckURL(rawPath, c)
			if matches == nil {
				c.AbortWithStatus(http.StatusNotFound)
				logWarning("%s %s %s %s %s 404-NOMATCH", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto)
				return
			}
		*/

		// 若匹配api.github.com/repos/用户名/仓库名/路径, 则检查是否开启HeaderAuth

		// 处理blob/raw路径
		if matcher == "blob" {
			rawPath = strings.Replace(rawPath, "/blob/", "/raw/", 1)
		}

		// 鉴权
		authcheck, err := auth.AuthHandler(c, cfg)
		if !authcheck {
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
			logWarning("%s %s %s %s %s Auth-Error: %v", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto, err)
			return
		}

		// IP METHOD URL USERAGENT PROTO MATCHES
		logDebug("%s %s %s %s %s Matches: %v", c.ClientIP(), c.Request.Method, rawPath, c.Request.Header.Get("User-Agent"), c.Request.Proto, matches)

		switch matcher {
		case "releases", "blob", "raw", "gist", "api":
			//ProxyRequest(c, rawPath, cfg, "chrome", runMode)
			ChunkedProxyRequest(c, rawPath, cfg, "chrome", runMode) // dev test chunk
		case "clone":
			//ProxyRequest(c, rawPath, cfg, "git", runMode)
			GitReq(c, rawPath, cfg, "git", runMode)
		default:
			c.String(http.StatusForbidden, "Invalid input.")
			fmt.Println("Invalid input.")
			return
		}
	}
}

/*
func CheckURL(u string, c *gin.Context) []string {
	for _, exp := range exps {
		if matches := exp.FindStringSubmatch(u); matches != nil {
			return matches[1:]
		}
	}
	errMsg := fmt.Sprintf("%s %s %s %s %s Invalid URL", c.ClientIP(), c.Request.Method, u, c.Request.Header.Get("User-Agent"), c.Request.Proto)
	logError(errMsg)
	return nil
}
*/
