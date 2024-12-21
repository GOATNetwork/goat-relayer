package migrations

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Migration represents a database migration record
type Migration struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"uniqueIndex;not null"`
	AppliedAt time.Time `gorm:"not null"`
}

// MigrationManager handles database migrations
type MigrationManager struct {
	db *gorm.DB
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *gorm.DB) *MigrationManager {
	return &MigrationManager{db: db}
}

// EnsureMigrationTable ensures the migrations table exists
func (m *MigrationManager) EnsureMigrationTable() error {
	if !m.db.Migrator().HasTable(&Migration{}) {
		log.Debugf("Creating migrations table")
		return m.db.AutoMigrate(&Migration{})
	}
	return nil
}

// HasMigration checks if a migration has been applied
func (m *MigrationManager) HasMigration(name string) bool {
	var count int64
	err := m.db.Transaction(func(tx *gorm.DB) error {
		return tx.Model(&Migration{}).Where("name = ?", name).Count(&count).Error
	})
	return err == nil && count > 0
}

// RecordMigration records that a migration has been applied
func (m *MigrationManager) RecordMigration(name string) error {
	migration := &Migration{
		Name:      name,
		AppliedAt: time.Now(),
	}
	result := m.db.Create(migration)
	if result.Error != nil {
		return fmt.Errorf("failed to record migration %s: %w", name, result.Error)
	}
	log.Debugf("Recorded migration: %s", name)
	return nil
}

// RunMigration runs a migration if it hasn't been applied yet
func (m *MigrationManager) RunMigration(name string, migrationFn func(*gorm.DB) error) error {
	// Use a dedicated transaction for checking migration status
	var exists bool
	err := m.db.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&Migration{}).Where("name = ?", name).Count(&count).Error; err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}
		exists = count > 0
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}

	if exists {
		log.Debugf("Migration %s has already been applied, skipping", name)
		return nil
	}

	log.Debugf("Running migration: %s", name)

	// Create a new session with our desired configuration
	session := m.db.Session(&gorm.Session{
		PrepareStmt: true,
	})

	// Use the configured session for the migration transaction
	err = session.Transaction(func(tx *gorm.DB) error {
		// Double-check migration status within transaction
		var count int64
		if err := tx.Model(&Migration{}).Where("name = ?", name).Count(&count).Error; err != nil {
			return fmt.Errorf("failed to check migration status: %w", err)
		}
		if count > 0 {
			return nil
		}

		// Run the migration
		if err := migrationFn(tx); err != nil {
			return fmt.Errorf("migration %s failed: %w", name, err)
		}

		// Record the migration
		migration := &Migration{
			Name:      name,
			AppliedAt: time.Now(),
		}
		if err := tx.Create(migration).Error; err != nil {
			return fmt.Errorf("failed to record migration %s: %w", name, err)
		}

		log.Debugf("Recorded migration: %s", name)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to run migration %s: %w", name, err)
	}

	log.Debugf("Successfully completed migration: %s", name)
	return nil
}
