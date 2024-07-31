package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"path/filepath"
	"os"
)

func setupDB(dbpath string) (*sql.DB, error){
	abspath, err := filepath.Abs(dbpath)
	if err != nil {
		return nil, err
	}

	dirname := filepath.Dir(abspath)

	if _, err := os.Stat(dirname); os.IsNotExist(err) {
		err := os.MkdirAll(dirname, 0755)
		if err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS macs (mac TEXT PRIMARY KEY, ip TEXT)")
	if err != nil {
		return nil, err
	}

	return db, nil
}

func loadAll(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query("SELECT mac, ip FROM macs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	macs := make(map[string]string)
	for rows.Next() {
		var mac, ip string
		err := rows.Scan(&mac, &ip)
		if err != nil {
			return nil, err
		}
		macs[ip] = mac
	}
	return macs, nil
}

func saveAll(db *sql.DB, replyChannel chan Reply) {
	for macs := range replyChannel {
		tx, err := db.Begin()
		if err != nil {
			log.Printf("db error: %s\n", err)
		}

		stmt, err := tx.Prepare("INSERT OR REPLACE INTO macs(mac, ip) VALUES(?, ?)")
		if err != nil {
			log.Printf("db error: %s\n", err)
		}
		defer stmt.Close()

		_, err = stmt.Exec(macs.Mac.String(), macs.Ip.String())
		if err != nil {
			log.Printf("db error: %s\n", err)
		}

		err = tx.Commit()
		if err != nil {
			log.Printf("db error: %s\n", err)
		}
	}
}