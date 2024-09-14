package db

import (
	"os"
	"path/filepath"

	"github.com/goatnetwork/goat-relayer/internal/config"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type DatabaseManager struct {
	l2SyncDb   *gorm.DB
	l2InfoDb   *gorm.DB
	btcLightDb *gorm.DB
	walletDb   *gorm.DB
	btcCacheDb *gorm.DB
}

func NewDatabaseManager() *DatabaseManager {
	dm := &DatabaseManager{}
	dm.initDB()
	return dm
}

func (dm *DatabaseManager) initDB() {
	dbDir := config.AppConfig.DbDir
	if err := os.MkdirAll(dbDir, os.ModePerm); err != nil {
		log.Fatalf("Failed to create database directory: %v", err)
	}

	l2SyncPath := filepath.Join(dbDir, "l2_sync.db")
	l2SyncDb, err := gorm.Open(sqlite.Open(l2SyncPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database 1: %v", err)
	}
	dm.l2SyncDb = l2SyncDb
	log.Debugf("Database 1 connected successfully, path: %s", l2SyncPath)

	l2InfoPath := filepath.Join(dbDir, "l2_info.db")
	l2InfoDb, err := gorm.Open(sqlite.Open(l2InfoPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database 2: %v", err)
	}
	dm.l2InfoDb = l2InfoDb
	log.Debugf("Database 2 connected successfully, path: %s", l2InfoPath)

	btcLightPath := filepath.Join(dbDir, "btc_light.db")
	btcLightDb, err := gorm.Open(sqlite.Open(btcLightPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database 3: %v", err)
	}
	dm.btcLightDb = btcLightDb
	log.Debugf("Database 3 connected successfully, path: %s", btcLightPath)

	walletPath := filepath.Join(dbDir, "wallet_order.db")
	walletDb, err := gorm.Open(sqlite.Open(walletPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database 4: %v", err)
	}
	dm.walletDb = walletDb
	log.Debugf("Database 4 connected successfully, path: %s", walletPath)

	btcCachePath := filepath.Join(dbDir, "btc_cache.db")
	btcCacheDb, err := gorm.Open(sqlite.Open(btcCachePath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database 5: %v", err)
	}
	dm.btcCacheDb = btcCacheDb
	log.Debugf("Database 5 connected successfully, path: %s", btcCachePath)

	dm.autoMigrate()
	log.Debugf("Database migration completed successfully")
}

func (dm *DatabaseManager) GetL2SyncDB() *gorm.DB {
	return dm.l2SyncDb
}

func (dm *DatabaseManager) GetL2InfoDB() *gorm.DB {
	return dm.l2InfoDb
}

func (dm *DatabaseManager) GetBtcLightDB() *gorm.DB {
	return dm.btcLightDb
}

func (dm *DatabaseManager) GetWalletDB() *gorm.DB {
	return dm.walletDb
}

func (dm *DatabaseManager) GetBtcCacheDB() *gorm.DB {
	return dm.btcCacheDb
}
