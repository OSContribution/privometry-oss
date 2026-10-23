// Package timelineweb holds the browser timeline's static files, which
// privometry timeline --web serves from the binary.
package timelineweb

import "embed"

// Files is index.html and the files it loads.
//
//go:embed index.html app.js style.css
var Files embed.FS
