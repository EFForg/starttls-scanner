package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/stats"

	// Imports postgresql driver for database/sql
	_ "github.com/lib/pq"
)

// Format string for Sql timestamps.
const sqlTimeFormat = "2006-01-02 15:04:05"

// SQLDatabase is a Database interface backed by postgresql.
type SQLDatabase struct {
	cfg             Config  // Configuration to define the DB connection.
	conn            *sql.DB // The database connection.
	PendingPolicies *PolicyDB
	Policies        *PolicyDB
}

func getConnectionString(cfg Config) string {
	connectionString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		url.PathEscape(cfg.DbUsername),
		url.PathEscape(cfg.DbPass),
		url.PathEscape(cfg.DbHost),
		url.PathEscape(cfg.DbName))
	return connectionString
}

// InitSQLDatabase creates a DB connection based on information in a Config, and
// returns a pointer the resulting SQLDatabase object. If connection fails,
// returns an error.
func InitSQLDatabase(cfg Config) (*SQLDatabase, error) {
	connectionString := getConnectionString(cfg)
	log.Printf("Connecting to Postgres DB ... \n")
	conn, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}
	return &SQLDatabase{cfg: cfg, conn: conn,
		PendingPolicies: &PolicyDB{tableName: "pending_policies", conn: conn, strict: false},
		Policies:        &PolicyDB{tableName: "policies", conn: conn, strict: true},
	}, nil
}

// TOKEN DB FUNCTIONS

// randToken generates a random token.
func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// UseToken sets the `used` flag on a particular email validation token to
// true, and returns the domain that was associated with the token.
func (db *SQLDatabase) UseToken(tokenStr string) (string, error) {
	var domain string
	err := db.conn.QueryRow("UPDATE tokens SET used=TRUE WHERE token=$1 AND used=FALSE RETURNING domain",
		tokenStr).Scan(&domain)
	return domain, err
}

// GetTokenByDomain gets the token for a domain name.
func (db *SQLDatabase) GetTokenByDomain(domain string) (string, error) {
	var token string
	err := db.conn.QueryRow("SELECT token FROM tokens WHERE domain=$1", domain).Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}

// PutToken generates and inserts a token into the database for a particular
// domain, and returns the resulting token row.
func (db *SQLDatabase) PutToken(domain string) (models.Token, error) {
	token := models.Token{
		Domain:  domain,
		Token:   randToken(),
		Expires: time.Now().Add(time.Duration(time.Hour * 72)),
		Used:    false,
	}
	_, err := db.conn.Exec("INSERT INTO tokens(domain, token, expires) VALUES($1, $2, $3) "+
		"ON CONFLICT (domain) DO UPDATE SET token=$2, expires=$3, used=FALSE",
		domain, token.Token, token.Expires.UTC().Format(sqlTimeFormat))
	if err != nil {
		return models.Token{}, err
	}
	return token, nil
}

// SCAN DB FUNCTIONS

// PutScan inserts a new scan for a particular domain into the database.
func (db *SQLDatabase) PutScan(scan models.Scan) error {
	// Serialize scanData.Data for insertion into SQLdb!
	// @TODO marshall scan adds extra fields - need a custom obj for this
	byteArray, err := json.Marshal(scan.Data)
	if err != nil {
		return err
	}
	// Extract MTA-STS Mode to column for querying by mode, eg. adoption stats.
	// Note, this will include MTA-STS configurations that serve a parse-able
	// policy file and define a mode but don't pass full validation.
	mtastsMode := ""
	if scan.Data.MTASTSResult != nil {
		mtastsMode = scan.Data.MTASTSResult.Mode
	}
	_, err = db.conn.Exec("INSERT INTO scans(domain, scandata, timestamp, version, mta_sts_mode) VALUES($1, $2, $3, $4, $5)",
		scan.Domain, string(byteArray), scan.Timestamp.UTC().Format(sqlTimeFormat), scan.Version, mtastsMode)
	return err
}

// GetStats returns statistics about a MTA-STS adoption from a single
// source domains to check.
func (db *SQLDatabase) GetStats(source string) (stats.Series, error) {
	series := stats.Series{}
	rows, err := db.conn.Query(
		`SELECT time, source, with_mxs, mta_sts_testing, mta_sts_enforce
		FROM aggregated_scans
		WHERE source=$1
		ORDER BY time`, source)
	if err != nil {
		return series, err
	}
	defer rows.Close()
	for rows.Next() {
		var a checker.AggregatedScan
		if err := rows.Scan(&a.Time, &a.Source, &a.WithMXs, &a.MTASTSTesting, &a.MTASTSEnforce); err != nil {
			return series, err
		}
		series = append(series, a)
	}
	return series, nil
}

// PutLocalStats writes aggregated stats for the 14 days preceding `date` to
// the aggregated_stats table.
func (db *SQLDatabase) PutLocalStats(date time.Time) (checker.AggregatedScan, error) {
	query := `
		SELECT
			COUNT(domain) AS total,
			COALESCE ( SUM (
				CASE WHEN mta_sts_mode = 'testing' THEN 1 ELSE 0 END
			), 0 ) AS testing,
			COALESCE ( SUM (
				CASE WHEN mta_sts_mode = 'enforce' THEN 1 ELSE 0 END
			), 0 ) AS enforce
		FROM (
			SELECT DISTINCT ON (domain) domain, timestamp, mta_sts_mode
			FROM scans
			WHERE timestamp BETWEEN $1 AND $2
			ORDER BY domain, timestamp DESC
		) AS latest_domains;
	`
	start := date.Add(-14 * 24 * time.Hour)
	end := date
	a := checker.AggregatedScan{
		Source: checker.LocalSource,
		Time:   date,
	}
	err := db.conn.QueryRow(query, start.UTC(), end.UTC()).Scan(&a.WithMXs, &a.MTASTSTesting, &a.MTASTSEnforce)
	if err != nil {
		return a, err
	}
	err = db.PutAggregatedScan(a)
	return a, err
}

const mostRecentQuery = `
SELECT domain, scandata, timestamp, version FROM scans
    WHERE timestamp = (SELECT MAX(timestamp) FROM scans WHERE domain=$1)
`

// GetLatestScan retrieves the most recent scan performed on a particular email
// domain.
func (db SQLDatabase) GetLatestScan(domain string) (models.Scan, error) {
	var rawScanData []byte
	result := models.Scan{}
	err := db.conn.QueryRow(mostRecentQuery, domain).Scan(
		&result.Domain, &rawScanData, &result.Timestamp, &result.Version)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(rawScanData, &result.Data)
	return result, err
}

// GetAllScans retrieves all the scans performed for a particular domain.
func (db SQLDatabase) GetAllScans(domain string) ([]models.Scan, error) {
	rows, err := db.conn.Query(
		"SELECT domain, scandata, timestamp, version FROM scans WHERE domain=$1", domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scans := []models.Scan{}
	for rows.Next() {
		var scan models.Scan
		var rawScanData []byte
		if err := rows.Scan(&scan.Domain, &rawScanData, &scan.Timestamp, &scan.Version); err != nil {
			return nil, err
		}
		err = json.Unmarshal(rawScanData, &scan.Data)
		scans = append(scans, scan)
	}
	return scans, nil
}

// EMAIL BLACKLIST DB FUNCTIONS

// PutBlacklistedEmail adds a bounce or complaint notification to the email blacklist.
func (db SQLDatabase) PutBlacklistedEmail(email string, reason string, timestamp string) error {
	_, err := db.conn.Exec("INSERT INTO blacklisted_emails(email, reason, timestamp) VALUES($1, $2, $3)",
		email, reason, timestamp)
	return err
}

// IsBlacklistedEmail returns true iff we've blacklisted the passed email address for sending.
func (db SQLDatabase) IsBlacklistedEmail(email string) (bool, error) {
	var count int
	row := db.conn.QueryRow("SELECT COUNT(*) FROM blacklisted_emails WHERE email=$1", email)
	err := row.Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func tryExec(database SQLDatabase, commands []string) error {
	for _, command := range commands {
		if _, err := database.conn.Exec(command); err != nil {
			return fmt.Errorf("command failed: %s\nwith error: %v",
				command, err.Error())
		}
	}
	return nil
}

// ClearTables nukes all the tables. ** Should only be used during testing **
func (db SQLDatabase) ClearTables() error {
	return tryExec(db, []string{
		fmt.Sprintf("DELETE FROM %s", db.cfg.DbDomainTable),
		fmt.Sprintf("DELETE FROM %s", db.cfg.DbScanTable),
		fmt.Sprintf("DELETE FROM %s", db.cfg.DbTokenTable),
		fmt.Sprintf("DELETE FROM %s", "hostname_scans"),
		fmt.Sprintf("DELETE FROM %s", "blacklisted_emails"),
		fmt.Sprintf("DELETE FROM %s", "aggregated_scans"),
		fmt.Sprintf("DELETE FROM %s", "policies"),
		fmt.Sprintf("DELETE FROM %s", "pending_policies"),
		fmt.Sprintf("ALTER SEQUENCE %s_id_seq RESTART WITH 1", db.cfg.DbScanTable),
	})
}

// GetHostnameScan retrives most recent scan from database.
func (db *SQLDatabase) GetHostnameScan(hostname string) (checker.HostnameResult, error) {
	result := checker.HostnameResult{
		Hostname: hostname,
		Result:   &checker.Result{},
	}
	var rawScanData []byte
	err := db.conn.QueryRow(`SELECT timestamp, status, scandata FROM hostname_scans
                    WHERE hostname=$1 AND
                    timestamp=(SELECT MAX(timestamp) FROM hostname_scans WHERE hostname=$1)`,
		hostname).Scan(&result.Timestamp, &result.Status, &rawScanData)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(rawScanData, &result.Checks)
	return result, err
}

// PutHostnameScan puts this scan into the database.
func (db *SQLDatabase) PutHostnameScan(hostname string, result checker.HostnameResult) error {
	data, err := json.Marshal(result.Checks)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`INSERT INTO hostname_scans(hostname, status, scandata)
                                VALUES($1, $2, $3)`, hostname, result.Status, string(data))
	return err
}

// PutAggregatedScan writes and AggregatedScan to the db.
func (db *SQLDatabase) PutAggregatedScan(a checker.AggregatedScan) error {
	_, err := db.conn.Exec(`INSERT INTO
		aggregated_scans(time, source, attempted, with_mxs, mta_sts_testing, mta_sts_enforce)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (time,source) DO NOTHING`,
		a.Time, a.Source, a.Attempted, a.WithMXs, a.MTASTSTesting, a.MTASTSEnforce)
	return err
}
