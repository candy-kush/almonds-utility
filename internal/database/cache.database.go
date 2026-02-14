package database

import (
	"time"

	"github.com/patrickmn/go-cache"
)

func InitGoCache() *cache.Cache {
	return cache.New(
		10*time.Minute, // default expiration
		15*time.Minute, // cleanup interval
	)
}