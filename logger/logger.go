package logger

import (
	"fmt"
	"os"
	"regexp"
	"runtime"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func Middleware(appName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionId := session.Get("loggerSessionId")
		if sessionId == nil {
			sessionId = uuid.New().String()
			session.Set("loggerSessionId", sessionId)
			err := session.Save()
			if err != nil {
				println("cannot save in session")
				return
			}
		}
		logger := logrus.New()
		configureLogger(logger, appName)
		loggerEntry := logger.WithContext(c.Request.Context()).WithFields(logrus.Fields{
			"method":    c.Request.Method,
			"path":      c.Request.URL.Path,
			"requestId": uuid.New(),
			"sessionId": sessionId,
		})
		c.Set("logger", loggerEntry)
	}
}

func configureLogger(logger *logrus.Logger, appName string) {
	logger.SetReportCaller(true)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			re := regexp.MustCompile("^.*?" + appName + "/")
			cleanPath := re.ReplaceAllString(f.File, "")
			return fmt.Sprintf(""), fmt.Sprintf("%s:%d", cleanPath, f.Line)
		},
	})
	if os.Getenv("ENV") != "prod" {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
}
