package log

import "testing"

func TestLog(t *testing.T) {
	LogLevel = 3
	DebugLog("debug")
	InfoLog("info")
	WarnLog("warn")
	ErrorLog("err")
}
