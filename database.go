package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

func setupDB(dbpath string) (*bbolt.DB, error) {
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
	db, err := bbolt.Open(abspath, 0600, nil)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func loadAll(db *bbolt.DB) (map[string]string, error) {
	macs := make(map[string]string)
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("macs"))
		if b == nil {
			return nil
		}
		b.ForEach(func(k, v []byte) error {
			macs[string(k)] = string(v)
			return nil
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return macs, nil
}

func saveAll(db *bbolt.DB, replyChannel <-chan Reply, batchSize int, flushInterval time.Duration) {
	if batchSize < 1 {
		batchSize = 1
	}
	if flushInterval <= 0 {
		flushInterval = time.Second
	}

	pending := make([]Reply, 0, batchSize)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(pending) == 0 {
			return
		}

		updates := make(map[string]string, len(pending))
		for _, macs := range pending {
			key := macKey(macs)
			updates[key] = strings.TrimSpace(macs.Mac.String())
		}

		err := db.Update(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("macs"))
			if err != nil {
				return err
			}
			for key, mac := range updates {
				if err := b.Put([]byte(key), []byte(mac)); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("error saving macs: %v\n", err)
		}
		pending = pending[:0]
	}

	for {
		select {
		case macs, ok := <-replyChannel:
			if !ok {
				flush()
				return
			}
			pending = append(pending, macs)
			if len(pending) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
