package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserPrefsSetLastWatchedAndTrim(t *testing.T) {
	u := &User{}
	require.NoError(t, u.SetLastWatched("/folder/a", "/folder/a/ep1.mkv"))
	require.NoError(t, u.SetLastWatched("/folder/b", "/folder/b/ep2.mkv"))

	m := u.LastWatchedMap()
	require.Equal(t, "/folder/a/ep1.mkv", m["/folder/a"])
	require.Equal(t, "/folder/b/ep2.mkv", m["/folder/b"])

	prefs := u.GetPrefs()
	prefs.LastWatched["/old"] = LastWatchedEntry{File: "/old/x.mkv", UpdatedAt: 1}
	for i := 0; i < maxLastWatchedEntries; i++ {
		key := "/bulk/" + string(rune('a'+i%26)) + string(rune('0'+i%10))
		prefs.LastWatched[key] = LastWatchedEntry{
			File:      key + "/f.mkv",
			UpdatedAt: int64(10 + i),
		}
	}
	require.NoError(t, u.SetPrefs(prefs))
	require.NoError(t, u.SetLastWatched("/folder/c", "/folder/c/ep3.mkv"))
	require.LessOrEqual(t, len(u.GetPrefs().LastWatched), maxLastWatchedEntries)
	require.Equal(t, "/folder/c/ep3.mkv", u.LastWatchedMap()["/folder/c"])
}
