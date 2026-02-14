package middleware

import (
	"context"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type contextKey string

const (
	RequestIDKey contextKey = "reqId"
	IPKey        contextKey = "ip"
)

func RequestContext() gin.HandlerFunc {

	return func(c *gin.Context) {

		start := time.Now()

		// ---------- FAST REQUEST ID ----------
		reqID := strconv.Itoa((rand.Intn(9000000) + 1000000))
		
		// ---------- CLIENT IP ----------
		ip := extractClientIP(c)

		// ---------- CONTEXT INJECTION (single allocation) ----------
		ctx := context.WithValue(c.Request.Context(), RequestIDKey, reqID)
		ctx = context.WithValue(ctx, IPKey, ip)
		c.Request = c.Request.WithContext(ctx)

		// ---------- PROCESS ----------
		c.Next()

		// POST Response 
		latency := time.Since(start)

		slog.Info("HTTP Request",
			"reqId", reqID,
			"ip", ip,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latencyMs", latency.Milliseconds(),
		)
	}
}

// ---------------------------------------------------

func extractClientIP(c *gin.Context) string {

	// Prefer X-Forwarded-For (first IP only, no split allocation)
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {

		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}

		return strings.TrimSpace(xff)
	}

	// Nginx header
	if xrip := c.GetHeader("X-Real-IP"); xrip != "" {
		return xrip
	}

	ip := c.ClientIP()

	// Normalize localhost
	if ip == "::1" {
		return "127.0.0.1"
	}

	// Remove IPv6 mapped prefix
	if after, ok :=strings.CutPrefix(ip, "::ffff:"); ok  {
		ip = after
	}

	// Validate IP (safety)
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}

	return ip
}
