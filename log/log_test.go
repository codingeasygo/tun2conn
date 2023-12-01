package log

import "testing"

func TestLog(t *testing.T) {
	DebugLog("debug")
	InfoLog("info")
	WarnLog("warn")
	ErrorLog("err")
}
