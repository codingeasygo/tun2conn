package gfw

import "os"

var Shared = NewCache(os.TempDir())
