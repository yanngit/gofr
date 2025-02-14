package gofr

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/yanngit/gofr/auth"
	"github.com/yanngit/gofr/logger"
)

type Server struct {
	*gin.Engine
	AuthMiddleware *auth.Middleware
}

func NewServer(appName string) *Server {
	r := gin.Default()
	/*Create store to manage session cookies (will encrypt them)*/
	sessionName := "authentication"
	logrus.Debugf("Creating session store named %s", sessionName)
	store := cookie.NewStore([]byte("secretForCookieSession"))
	store.Options(sessions.Options{MaxAge: 60 * 60 * 24 * 7, HttpOnly: true, Path: "/"}) // expires in a week
	/*Adding session*/
	/*Adding logger middleware for logger stored in context*/
	r.Use(sessions.Sessions(sessionName, store), logger.LoggerMiddleware(appName))
	authMiddleware := auth.NewAuthMiddleware()
	authController := auth.NewAuthController()
	authController.Handle(r)
	return &Server{
		r,
		authMiddleware,
	}
}

func (gf *Server) GetAuthMiddleware() *auth.Middleware {
	return gf.AuthMiddleware
}
