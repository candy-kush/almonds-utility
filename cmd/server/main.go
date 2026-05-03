package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/secure"
	"github.com/joho/godotenv"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"almonds-utility/internal/database"
	"almonds-utility/internal/handlers"
	"almonds-utility/internal/middleware"
	"almonds-utility/internal/service"

	"github.com/gin-gonic/gin"
)

var BuildVersion = "build"

func main() {
	godotenv.Load()
	gin.SetMode(os.Getenv("GIN_MODE"))

	// Initialize Logger
	middleware.InitLogger(BuildVersion)

	// Initialize Router
	router := gin.New()

	router.Use(gin.Recovery())
	router.Use(middleware.RequestContext())

	router.SetTrustedProxies(nil) 

	// B. Security Headers
	router.Use(secure.New(secure.Config{
		SSLRedirect:           false, // Set to true if you want to force HTTPS
		STSSeconds:            315360000,
		STSIncludeSubdomains:  true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
	}))

	// C. CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Change * to specific domain in production
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept-Encoding", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// D. Compression 
	router.Use(gzip.Gzip(gzip.DefaultCompression))

	// Gin doesn't have a direct "json limit" middleware
	router.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 100*1024)
		c.Next()
	})

	// F. Rate Limiter
	// 10 reqs per 1 minute
	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  10,
	}
	store := memory.NewStore()
	instance := limiter.New(store, rate)
	
	// Custom handler
	rateMiddleware := mgin.NewMiddleware(instance, mgin.WithLimitReachedHandler(func(c *gin.Context) {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"message": "Too many requests, please try again later.",
			"code":    429,
		})
	}))
	
	router.Use(rateMiddleware)


	mySql, err := database.InitMySqlClient()
    if err != nil {
        fmt.Printf("Failed to initialize database: %v", err)
    }
    defer mySql.Write.Close()
    defer mySql.Read.Close()

	cache := database.InitGoCache()

	// Initialize Service and Handler
	utilService := service.NewUtilityService(mySql, cache)
	utilHandler := handlers.NewUtilityHandler(utilService)

	api := router.Group("/apis")

	// Routes
	v1 := api.Group("/v1/utils", middleware.AuthMiddleware(mySql, cache))
	{
		v1.POST("/pdf", utilHandler.GeneratePDF)
		v1.POST("/qr", utilHandler.GenerateQR)
		v1.GET("/keyIv", utilHandler.GenerateKeyIV)
		v1.GET("/uuid", utilHandler.GenerateUUID)
		v1.POST("/password", utilHandler.GeneratePassword)
		v1.POST("/hash", utilHandler.HashWithKey)
		v1.POST("/collision", utilHandler.CollisionProbability)
		v1.POST("/entropy", utilHandler.CalculateEntropy)
		v1.POST("/aes/encrypt", utilHandler.EncryptAESGCM)
		v1.POST("/aes/decrypt", utilHandler.DecryptAESGCM)
		v1.POST("/aes/key-hmac", utilHandler.AESKeyHmacPair)
		v1.GET("/basic-auth", utilHandler.GenerateBasicAuth)
		v1.POST("/random-string", utilHandler.GenerateRandom)
	}

	SERVER_PORT := os.Getenv("SERVER_PORT")
	if SERVER_PORT == "" {
		SERVER_PORT = "8080"
	}

	// Create HTTP server
	server := &http.Server{
		Addr:    ":" + SERVER_PORT,
		Handler: router, // your gin router
	}

	// Start server in goroutine
	go func() {
		slog.Info("Starting server on PORT " + SERVER_PORT)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Create shutdown channel
	quit := make(chan os.Signal, 1)

	// Listen for SIGINT (Ctrl+C) and SIGTERM (Docker/K8s stop)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit // Block until signal received

	slog.Info("Shutdown signal received. Gracefully shutting down...")

	// Timeout context for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Forced to shutdown", "error", err)
	}

	slog.Info("Server exiting properly")
}

// go build -ldflags="-X main.BuildVersion=1.0.4" -o bin/almonds-utility cmd/server/main.go