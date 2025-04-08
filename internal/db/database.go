package db

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db/migrations"
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

	databaseConfigs := []struct {
		dbPath string
		dbRef  **gorm.DB
		dbName string
	}{
		{filepath.Join(dbDir, "l2_sync.db"), &dm.l2SyncDb, "Database 1"},
		{filepath.Join(dbDir, "l2_info.db"), &dm.l2InfoDb, "Database 2"},
		{filepath.Join(dbDir, "btc_light.db"), &dm.btcLightDb, "Database 3"},
		{filepath.Join(dbDir, "wallet_order.db"), &dm.walletDb, "Database 4"},
		{filepath.Join(dbDir, "btc_cache.db"), &dm.btcCacheDb, "Database 5"},
	}

	for _, dbConfig := range databaseConfigs {
		if err := dm.connectDatabase(dbConfig.dbPath, dbConfig.dbRef, dbConfig.dbName); err != nil {
			log.Fatalf("Failed to connect to %s: %v", dbConfig.dbName, err)
		}
	}

	// First run auto migrations to create all necessary tables
	dm.autoMigrate()

	// Then run data migrations
	if err := dm.runMigrations(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Debugf("Database migration completed successfully")
}

func (dm *DatabaseManager) connectDatabase(dbPath string, dbRef **gorm.DB, dbName string) error {
	// Configure SQLite with WAL mode and busy timeout
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=10000&_synchronous=NORMAL", dbPath)

	// open database with configured settings
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
		// Enable auto retry on database lock
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", dbName, err)
	}

	*dbRef = db
	log.Debugf("%s connected successfully with WAL mode, path: %s", dbName, dbPath)
	return nil
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

func (dm *DatabaseManager) runMigrations() error {
	// Initialize migration managers for each database
	migrationManagers := map[string]*migrations.MigrationManager{
		"wallet": migrations.NewMigrationManager(dm.walletDb),
	}

	// Ensure migration tables exist
	for name, manager := range migrationManagers {
		log.Debugf("Ensuring migration table exists for %s database", name)
		if err := manager.EnsureMigrationTable(); err != nil {
			return fmt.Errorf("failed to create migration table for %s: %w", name, err)
		}
	}

	// Run migrations for wallet database
	log.Debugf("Running UTXO records migration")
	migrates := make(map[string](func(*gorm.DB) error), 0)
	if config.AppConfig.L2ChainId.String() == "2345" && config.AppConfig.BTCNetworkType == "mainnet" {
		migrates["20241220_2345_add_utxo_records"] = migrations.AddUtxoRecords
	}

	for name, migrate := range migrates {
		if err := migrationManagers["wallet"].RunMigration(name, migrate); err != nil {
			return fmt.Errorf("failed to run UTXO records migration: %w", err)
		}
	}

	return nil
}
