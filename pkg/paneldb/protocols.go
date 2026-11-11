package paneldb

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

var VPNProtocols = []string{"wdtt", "qwdtt", "wdtt-plus", "csqtt-2.1.9", "csqtt-2.5.0", "freeturn"}

func ValidateProtocols(protocols []string) error {
	seen := map[string]bool{}
	for _, name := range protocols {
		valid := false
		for _, allowed := range VPNProtocols {
			if name == allowed {
				valid = true
			}
		}
		if !valid || seen[name] {
			return fmt.Errorf("некорректный или повторный инбаунд: %s", name)
		}
		seen[name] = true
	}
	return nil
}

func UserProtocols(db *sql.DB, subID string) ([]string, error) {
	var raw string
	err := db.QueryRow(`SELECT protocols FROM vpn_user_inbounds WHERE sub_id=?`, subID).Scan(&raw)
	if err == sql.ErrNoRows {
		return []string{"wdtt"}, nil
	}
	if err != nil {
		return nil, err
	}
	result := []string{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return result, ValidateProtocols(result)
}

func SetUserProtocols(db *sql.DB, subID string, protocols []string) error {
	if subID == "" {
		return fmt.Errorf("у пользователя нет идентификатора подписки")
	}
	if err := ValidateProtocols(protocols); err != nil {
		return err
	}
	if protocols == nil {
		protocols = []string{}
	}
	raw, err := json.Marshal(protocols)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO vpn_user_inbounds(sub_id,protocols) VALUES(?,?) ON CONFLICT(sub_id) DO UPDATE SET protocols=excluded.protocols`, subID, string(raw)); err != nil {
		return err
	}
	if err := bumpUsersRevInTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}
