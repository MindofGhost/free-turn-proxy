package vkauth

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/statedir"
)

// CredentialsStateFile stores short-lived TURN credentials between process restarts.
const CredentialsStateFile = "vk_credentials.json"

type credentialsState struct {
	Entries map[string]TurnCredentials `json:"entries"`
}

type credentialsStore struct {
	paths []string
}

// credMu serializes read-modify-write cycles for the process-wide credentials file.
//
//nolint:gochecknoglobals // one file writer per process
var credMu sync.Mutex

func (s credentialsStore) load(cacheID int, link string, now time.Time) (TurnCredentials, bool) {
	if len(s.paths) == 0 {
		return TurnCredentials{}, false
	}
	for _, b := range statedir.ReadEach(s.paths) {
		st, ok := parseCredentialsState(b)
		if !ok {
			continue
		}
		creds, ok := st.Entries[cacheKey(cacheID)]
		if ok && creds.Link == link && creds.ExpiresAt.After(now) && len(creds.ServerAddrs) > 0 {
			return creds, true
		}
	}
	return TurnCredentials{}, false
}

func (s credentialsStore) save(cacheID int, creds TurnCredentials) bool {
	if len(s.paths) == 0 || creds.Username == "" || !creds.ExpiresAt.After(time.Now()) {
		return false
	}
	credMu.Lock()
	defer credMu.Unlock()

	st := s.read()
	st.Entries[cacheKey(cacheID)] = creds
	return s.write(st)
}

func (s credentialsStore) drop(cacheID int) bool {
	if len(s.paths) == 0 {
		return false
	}
	credMu.Lock()
	defer credMu.Unlock()

	st := s.read()
	key := cacheKey(cacheID)
	if _, ok := st.Entries[key]; !ok {
		return false
	}
	delete(st.Entries, key)
	return s.write(st)
}

func (s credentialsStore) read() credentialsState {
	for _, b := range statedir.ReadEach(s.paths) {
		if st, ok := parseCredentialsState(b); ok {
			return st
		}
	}
	return credentialsState{Entries: map[string]TurnCredentials{}}
}

func parseCredentialsState(b []byte) (credentialsState, bool) {
	var st credentialsState
	if json.Unmarshal(b, &st) != nil {
		return credentialsState{}, false
	}
	if st.Entries == nil {
		st.Entries = map[string]TurnCredentials{}
	}
	return st, true
}

func (s credentialsStore) write(st credentialsState) bool {
	b, err := json.Marshal(st)
	if err != nil {
		return false
	}
	return statedir.WriteFirst(s.paths, b)
}

func cacheKey(cacheID int) string {
	return strconv.Itoa(cacheID)
}
