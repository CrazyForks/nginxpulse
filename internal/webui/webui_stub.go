//go:build !embed
// +build !embed

package webui

import "io/fs"

func AssetFS() (fs.FS, bool) {
	return nil, false
}
