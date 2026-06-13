package common

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// LogLevel controls verbosity.
type LogLevel int

const (
	LogError LogLevel = iota
	LogWarn
	LogInfo
	LogDebug
)

// ParseLogLevel converts a string to a LogLevel. Unknown strings return LogInfo.
func ParseLogLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LogDebug
	case "info":
		return LogInfo
	case "warn", "warning":
		return LogWarn
	case "error":
		return LogError
	default:
		return LogInfo
	}
}

// Logger is a levelled, component-tagged logger.
type Logger struct {
	level     LogLevel
	component string
	out       *log.Logger
}

// NewLogger creates a logger for component at the given level.
// w defaults to os.Stderr if nil.
func NewLogger(component string, level LogLevel, w io.Writer) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{
		level:     level,
		component: component,
		out:       log.New(w, "", 0),
	}
}

func (l *Logger) write(lvl LogLevel, tag, msg string, args ...interface{}) {
	if lvl > l.level {
		return
	}
	body := msg
	if len(args) > 0 {
		body = fmt.Sprintf(msg, args...)
	}
	l.out.Printf("%s [%s] [%s] %s",
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		tag, l.component, body)
}

func (l *Logger) Debug(msg string, args ...interface{}) { l.write(LogDebug, "DEBUG", msg, args...) }
func (l *Logger) Info(msg string, args ...interface{})  { l.write(LogInfo,  "INFO ", msg, args...) }
func (l *Logger) Warn(msg string, args ...interface{})  { l.write(LogWarn,  "WARN ", msg, args...) }
func (l *Logger) Error(msg string, args ...interface{}) { l.write(LogError, "ERROR", msg, args...) }
