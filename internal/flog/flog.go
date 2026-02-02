package flog

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

type Level int

const None Level = -1
const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
)

var (
	minLevel = Info
	logCh    = make(chan string, 1024)
	dropped  atomic.Uint64
)

// Dropped returns the number of log messages dropped due to channel full.
func Dropped() uint64 { return dropped.Load() }

var levelStrings = [...]string{
	Debug: "DEBUG",
	Info:  "INFO",
	Warn:  "WARN",
	Error: "ERROR",
	Fatal: "FATAL",
}

func init() {

}

func SetLevel(l int) {
	minLevel = Level(l)
	if l != -1 {
		go func() {
			for msg := range logCh {
				fmt.Fprint(os.Stdout, msg)
			}
		}()
	}
}

func logf(level Level, format string, args ...any) {
	if level < minLevel || minLevel == None {
		return
	}

	// Check channel capacity before formatting to avoid wasted allocations
	if len(logCh) == cap(logCh) {
		dropped.Add(1)
		return
	}

	for _, arg := range args {
		if err, ok := arg.(error); ok {
			err = WErr(err)
			if err == nil {
				return
			}
		}
	}

	var levelStr string
	if int(level) < len(levelStrings) {
		levelStr = levelStrings[level]
	} else {
		levelStr = "UNKNOWN"
	}

	now := time.Now().Format("2006-01-02 15:04:05.000")
	line := fmt.Sprintf("%s [%s] %s\n", now, levelStr, fmt.Sprintf(format, args...))

	select {
	case logCh <- line:
	default:
		dropped.Add(1)
	}
}

func (l Level) String() string {
	if int(l) >= 0 && int(l) < len(levelStrings) {
		return levelStrings[l]
	}
	if l == None {
		return "None"
	}
	return "UNKNOWN"
}

func Debugf(format string, args ...any) { logf(Debug, format, args...) }
func Infof(format string, args ...any)  { logf(Info, format, args...) }
func Warnf(format string, args ...any)  { logf(Warn, format, args...) }
func Errorf(format string, args ...any) { logf(Error, format, args...) }
func Fatalf(format string, args ...any) {
	logf(Fatal, format, args...)
	// flush logs (optional: small sleep to let goroutine write)
	time.Sleep(10 * time.Millisecond)
	os.Exit(1)
}

func Close() { close(logCh) }
