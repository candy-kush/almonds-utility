package middleware

import (
	"almonds-utility/internal/database"
	"almonds-utility/internal/models"
	"context"
	"net"
	"net/http"
	"time"

	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

func AuthMiddleware(mySql *database.MySQLClient, cache *cache.Cache) gin.HandlerFunc {

	allowedCIDRs := []string{
		"127.0.0.1/32",
		"::1/128",
		"10.0.0.0/8",
		"192.168.0.0/16",
	}

	var parsedCIDRs []*net.IPNet
	for _, cidr := range allowedCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedCIDRs = append(parsedCIDRs, ipnet)
		}
	}

	return func(c *gin.Context) {

		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		clientIP := net.ParseIP(c.ClientIP())

		for _, ipnet := range parsedCIDRs {
			if ipnet.Contains(clientIP) {
				slog.InfoContext(ctx, "Auth bypass via CIDR",
					"ip", clientIP.String(),
				)
				c.Next()
				return
			}
		}

		clientID := c.GetHeader("clientId")
		clientSecret := c.GetHeader("clientSecret")
		profileId := c.GetHeader("profileId")

		if clientID == "" || clientSecret == "" || profileId == "" {
			slog.WarnContext(ctx, "Authentication failed - missing headers",
				"ip", clientIP.String(),
				"clientId", clientID,
				"profileId", profileId,
			)

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "Missing authentication headers",
			})
			return
		}


		var profile *models.ClientProfile
		
		val, found := cache.Get(profileId)
		if found {
			profile = val.(*models.ClientProfile)
		}

		if found {
			slog.InfoContext(ctx, "Client profile found in the cache layer")
			profileIdCache := profile.ProfileID
			clientIDCache := profile.ClientID
			clientSecretCache := profile.ClientSecret

			if clientIDCache != clientID || profileIdCache != profileId || clientSecretCache != clientSecret {
				slog.WarnContext(ctx, "Authentication failed - invalid credentials",
					"ip", clientIP.String(),
					"clientId", clientID,
					"profileId", profileId,
				)

				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "Authentication failed, invalid credentials",
				})
				return
			}

		} else {
			slog.InfoContext(ctx, "Client profile not found in the cache layer, querying to DB")
			query := `
				SELECT 1
				FROM clients
				WHERE client_id = ?
				AND client_secret = ?
				AND profile_id = ?
				LIMIT 1
			`

			row := mySql.QueryRow(ctx, query, clientID, clientSecret, profileId)

			var exists int
			err := row.Scan(&exists)
			
			if err != nil {
				slog.WarnContext(ctx, "Authentication failed - invalid credentials",
					"ip", clientIP.String(),
					"clientId", clientID,
					"profileId", profileId,
					"error", err,
				)

				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"code":    401,
					"message": "Invalid credentials",
				})
				return
			}

			slog.InfoContext(ctx, "Updating cache with client profile data")
			profile := &models.ClientProfile{
				ProfileID:    profileId,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}
			cache.Set(profileId, profile, 10*time.Minute)
		}

		
		c.Set("clientId", clientID)
		c.Set("profileId", profileId)

		c.Next()
	}
}