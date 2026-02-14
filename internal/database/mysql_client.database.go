package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"
)

type MySQLClient struct {
	Write *sql.DB
	Read  *sql.DB
}

type MySQLConfig struct {
	Username string 
	Password string
	Host     string
	Port     string
	Database string

	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

func DefaultMySQLConfig() MySQLConfig {
	return MySQLConfig{
		Username : os.Getenv("MYSQL_USER"),
		Host : os.Getenv("MYSQL_REPLICA_HOST"),
		Port : os.Getenv("MYSQL_PORT"),
		Database : os.Getenv("MYSQL_DATABASE"),
		Password : os.Getenv("MYSQL_PASSWORD"),
		MaxOpenConns:    10,
		MaxIdleConns:    3,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 2 * time.Minute,
	}
}

func InitMySqlClient() (*MySQLClient, error) {

	writeCfg := DefaultMySQLConfig()
	writeCfg.Host = os.Getenv("MYSQL_PRIMARY_HOST")

	readCfg := DefaultMySQLConfig()
	readCfg.Host = os.Getenv("MYSQL_REPLICA_HOST")
	readCfg.MaxOpenConns = 20
	readCfg.MaxIdleConns = 5

	writeDB, err := NewMySQLConnection(writeCfg)
	if err != nil {
		fmt.Printf("Failed to initialize database: %v", err)
		return nil, err
	}

	readDB, err := NewMySQLConnection(readCfg)
	if err != nil {
		fmt.Printf("Failed to initialize database: %v", err)
		return nil, err
	}

	fmt.Printf("MySql RW nodes connected at %s:%s", readCfg.Host, readCfg.Port)

	return &MySQLClient{
		Write: writeDB,
		Read:  readDB,
	}, nil
}

func (c *MySQLClient) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.Write.ExecContext(ctx, query, args...)
}

func (c *MySQLClient) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return c.Read.QueryContext(ctx, query, args...)
}

func (c *MySQLClient) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return c.Read.QueryRowContext(ctx, query, args...)
}