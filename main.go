package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type config struct {
	Port                         string
	AuthSecret                   string
	AdminEmail                   string
	AdminPassword                string
	CORSAllowedOrigins           []string
	CORSAllowCredentials         bool
	ClientWebhookSecret          string
	OperatorWebhookSecret        string
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authClaims struct {
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
}

func main() {
	cfg := loadConfig()

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery(), requestLogger(), corsMiddleware(cfg.CORSAllowedOrigins, cfg.CORSAllowCredentials))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.HEAD("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	router.POST("/auth/login", func(c *gin.Context) {
		var req loginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		if !strings.EqualFold(strings.TrimSpace(req.Email), cfg.AdminEmail) || req.Password != cfg.AdminPassword {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		token, expiresAt, err := issueToken(cfg.AuthSecret, cfg.AdminEmail, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":     token,
			"expiresAt": expiresAt.UTC().Format(time.RFC3339Nano),
			"user": gin.H{
				"id":    "usr_1",
				"email": cfg.AdminEmail,
				"name":  "Main Master",
				"role":  "admin",
			},
		})
	})

	router.GET("/auth/me", authMiddleware(cfg.AuthSecret), func(c *gin.Context) {
		email, _ := c.Get("email")
		c.JSON(http.StatusOK, gin.H{
			"user": gin.H{
				"id":    "usr_1",
				"email": email,
				"name":  "Main Master",
				"role":  "admin",
			},
			"workspace": gin.H{
				"id":   "ws_main",
				"name": "Rendy CRM",
			},
		})
	})

	router.POST("/webhooks/telegram/client/:workspace/:secret", func(c *gin.Context) {
		if cfg.ClientWebhookSecret != "" && c.Param("secret") != cfg.ClientWebhookSecret {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid webhook secret"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	router.POST("/webhooks/telegram/operator", func(c *gin.Context) {
		if cfg.OperatorWebhookSecret != "" {
			if c.GetHeader("X-Telegram-Bot-Api-Secret-Token") != cfg.OperatorWebhookSecret {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid operator webhook secret"})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("backend listening on :%s", cfg.Port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadConfig() config {
	return config{
		Port:                  envOrDefault("PORT", "3000"),
		AuthSecret:            envOrDefault("AUTH_SECRET", "change-me-now"),
		AdminEmail:            envOrDefault("ADMIN_EMAIL", "operator@rendycrm.local"),
		AdminPassword:         envOrDefault("ADMIN_PASSWORD", "password"),
		CORSAllowedOrigins:    splitCSV(envOrDefault("CORS_ALLOWED_ORIGINS", "*")),
		CORSAllowCredentials:  envOrDefaultBool("CORS_ALLOW_CREDENTIALS", false),
		ClientWebhookSecret:   os.Getenv("TELEGRAM_CLIENT_WEBHOOK_SECRET"),
		OperatorWebhookSecret: os.Getenv("TELEGRAM_OPERATOR_WEBHOOK_SECRET"),
	}
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envOrDefaultBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("%s %s %d %s", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start).String())
	}
}

func corsMiddleware(origins []string, allowCredentials bool) gin.HandlerFunc {
	allowAll := len(origins) == 0 || (len(origins) == 1 && origins[0] == "*")

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowedOrigin := ""

		if allowAll {
			if allowCredentials {
				allowedOrigin = origin
			} else {
				allowedOrigin = "*"
			}
		} else if originAllowed(origin, origins) {
			allowedOrigin = origin
		}

		if allowedOrigin != "" {
			c.Header("Access-Control-Allow-Origin", allowedOrigin)
			c.Header("Vary", "Origin")
		}
		if allowCredentials && allowedOrigin != "" && allowedOrigin != "*" {
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		requestHeaders := strings.TrimSpace(c.GetHeader("Access-Control-Request-Headers"))
		if requestHeaders == "" {
			requestHeaders = "Authorization, Content-Type, X-Telegram-Bot-Api-Secret-Token"
		}
		c.Header("Access-Control-Allow-Headers", requestHeaders)
		c.Header("Access-Control-Max-Age", "600")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func originAllowed(origin string, patterns []string) bool {
	if strings.TrimSpace(origin) == "" {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Scheme == "" || originURL.Hostname() == "" {
		return false
	}
	host := originURL.Hostname()

	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == origin {
			return true
		}

		parts := strings.SplitN(pattern, "://*.", 2)
		if len(parts) != 2 {
			continue
		}
		scheme := parts[0]
		suffix := parts[1]
		if scheme != originURL.Scheme {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func issueToken(secret, email string, ttl time.Duration) (string, time.Time, error) {
	exp := time.Now().Add(ttl)
	claims := authClaims{
		Email: email,
		Exp:   exp.Unix(),
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	sign := signToken(secret, body)
	return body + "." + sign, exp, nil
}

func parseToken(secret, token string) (authClaims, error) {
	var claims authClaims
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claims, fmt.Errorf("bad token format")
	}
	body := parts[0]
	sign := parts[1]
	if !hmac.Equal([]byte(signToken(secret, body)), []byte(sign)) {
		return claims, fmt.Errorf("bad signature")
	}
	data, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return claims, err
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return claims, err
	}
	if claims.Exp <= time.Now().Unix() {
		return claims, fmt.Errorf("token expired")
	}
	return claims, nil
}

func signToken(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func authMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := strings.TrimSpace(c.GetHeader("Authorization"))
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token == "" || token == auth {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid auth header"})
			return
		}

		claims, err := parseToken(secret, token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("email", claims.Email)
		c.Next()
	}
}
