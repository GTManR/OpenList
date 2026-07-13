package model

import (
	"encoding/json"
	"sort"
	"time"
)

const maxLastWatchedEntries = 500

// UserPrefs holds per-user preference blobs stored in User.Prefs.
type UserPrefs struct {
	LastWatched map[string]LastWatchedEntry `json:"last_watched,omitempty"`
}

// LastWatchedEntry records the most recently watched file in a folder.
type LastWatchedEntry struct {
	File      string `json:"file"`
	UpdatedAt int64  `json:"updated_at"`
}

func (u *User) GetPrefs() UserPrefs {
	if u == nil || u.Prefs == "" {
		return UserPrefs{LastWatched: map[string]LastWatchedEntry{}}
	}
	var prefs UserPrefs
	if err := json.Unmarshal([]byte(u.Prefs), &prefs); err != nil {
		return UserPrefs{LastWatched: map[string]LastWatchedEntry{}}
	}
	if prefs.LastWatched == nil {
		prefs.LastWatched = map[string]LastWatchedEntry{}
	}
	return prefs
}

func (u *User) SetPrefs(prefs UserPrefs) error {
	if prefs.LastWatched == nil {
		prefs.LastWatched = map[string]LastWatchedEntry{}
	}
	raw, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	u.Prefs = string(raw)
	return nil
}

// SetLastWatched records folder -> file and trims oldest entries when over limit.
func (u *User) SetLastWatched(folder, file string) error {
	prefs := u.GetPrefs()
	prefs.LastWatched[folder] = LastWatchedEntry{
		File:      file,
		UpdatedAt: time.Now().Unix(),
	}
	trimLastWatched(prefs.LastWatched, maxLastWatchedEntries)
	return u.SetPrefs(prefs)
}

// LastWatchedMap returns folder -> file paths for API responses.
func (u *User) LastWatchedMap() map[string]string {
	prefs := u.GetPrefs()
	out := make(map[string]string, len(prefs.LastWatched))
	for folder, entry := range prefs.LastWatched {
		if entry.File != "" {
			out[folder] = entry.File
		}
	}
	return out
}

func trimLastWatched(entries map[string]LastWatchedEntry, limit int) {
	if len(entries) <= limit {
		return
	}
	type kv struct {
		key string
		at  int64
	}
	items := make([]kv, 0, len(entries))
	for key, entry := range entries {
		items = append(items, kv{key: key, at: entry.UpdatedAt})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].at < items[j].at
	})
	for i := 0; i < len(items)-limit; i++ {
		delete(entries, items[i].key)
	}
}
