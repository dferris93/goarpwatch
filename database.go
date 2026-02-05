package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

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

func saveAll(db *bbolt.DB, replyChannel chan Reply) {
	for macs := range replyChannel {
		err := db.Update(func(tx *bbolt.Tx) error {
			var b *bbolt.Bucket
			var err error
			b, err = tx.CreateBucketIfNotExists([]byte("macs"))
			if err != nil {
				return err
			}
			mac := strings.TrimSpace(macs.Mac.String())
			key := macKey(macs)
			err = b.Put([]byte(key), []byte(mac))
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			log.Printf("error saving macs: %v\n", err)
		}
	}
}
