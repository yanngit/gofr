package gofr

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/yanngit/gofr/controller"
)

type GoFr struct {
	*gin.Engine
	AuthMiddleware *controller.AuthMiddleware
}

func New(appName string) *GoFr {
	r := gin.Default()
	/*Create store to manage session cookies (will encrypt them)*/
	sessionName := "GoFr.login"
	logrus.Debugf("Creating session store named %s", sessionName)
	store := cookie.NewStore([]byte("secretForCookieSession"))
	store.Options(sessions.Options{MaxAge: 60 * 60 * 24 * 7, HttpOnly: true, Path: "/"}) // expires in a week
	/*Adding session*/
	/*Adding logger middleware for logger stored in context*/
	r.Use(sessions.Sessions(sessionName, store), loggerMiddleware(appName))
	authMiddleware := controller.NewAuthMiddleware()
	auth := controller.NewAuthController()
	auth.Handle(r)
	return &GoFr{
		r,
		authMiddleware,
	}
}

func (gf *GoFr) GetAuthMiddleware() *controller.AuthMiddleware {
	return gf.AuthMiddleware
}
