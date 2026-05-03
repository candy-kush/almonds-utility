package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// 1. Define the Custom Handler
type ContextHandler struct {
	slog.Handler
}

// 2. Implement the Handle method
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok {
		r.AddAttrs(slog.String("reqId", reqID))
	}
	if ip, ok := ctx.Value(IPKey).(string); ok {
		r.AddAttrs(slog.String("ip", ip))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithGroup(name)}
}

func InitLogger(version string) {

	level := strings.ToLower(os.Getenv("LOG_LEVEL"))

	var slogLevel slog.Level

	switch level {
		case "debug":
			slogLevel = slog.LevelDebug
		case "warn":
			slogLevel = slog.LevelWarn
		case "error":
			slogLevel = slog.LevelError
		default:
			slogLevel = slog.LevelInfo
	}

	// -------- LUMBERJACK ROTATOR --------

	// logPath := os.Getenv("LOG_PATH")
	// if logPath == "" {
	// 	logPath = "/opt/logs/almonds-utility/almonds-utility.out"
	// }

	// maxSize := getEnvAsInt("LOG_MAX_SIZE", 20)       // MB
	// maxBackups := getEnvAsInt("LOG_MAX_BACKUPS", 15)
	// maxDays := getEnvAsInt("LOG_MAX_DAYS", 15)

	// fileWriter := &lumberjack.Logger{
	// 	Filename:   logPath,
	// 	MaxSize:    maxSize,
	// 	MaxBackups: maxBackups,
	// 	MaxAge:     maxDays,
	// 	Compress:   true,
	// 	LocalTime:  true,
	// }

	// writer := io.MultiWriter(os.Stdout, fileWriter)

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slogLevel,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {

			// ---------- TIME (UTC + ms) ----------
			if a.Key == slog.TimeKey {
				t := a.Value.Time().UTC()
				return slog.Attr{
					Key:   "time",
					Value: slog.StringValue(t.Format("2006-01-02T15:04:05.000Z")),
				}
			}
			
			if a.Key == slog.SourceKey {
				if src, ok := a.Value.Any().(*slog.Source); ok {
					return slog.String("caller",
						fmt.Sprintf("%s:%d", filepath.Base(src.File), src.Line),
					)
				}
			}

			return a
		},
	})

	ctxHandler := &ContextHandler{Handler: handler}

	logger := slog.New(ctxHandler)
	logger = logger.With("version", version)

	slog.SetDefault(logger)
}

func getEnvAsInt(key string, defaultVal int) int {

	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}

	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}

	return val
}
