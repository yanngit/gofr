package gofr

import (
	"fmt"
	"os"

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

func verifyEnvVars() {
	logrus.Infof("Verifying env vars")
	envs := []string{"ENV", "PORT", "EXTERNAL_URL", "OIDC_HOST", "SERVER_CLIENT_SECRET", "SERVER_CLIENT_ID", "CLIENT_CLIENT_ID", "CODE_VERIFIER", "CODE_CHALLENGE", "CODE_CHALLENGE_METHOD"}
	for _, env := range envs {
		val, exists := os.LookupEnv(env)
		if !exists {
			panic(fmt.Sprintf("environment variable %s not set", env))
		}
		logrus.Infof("Using environment variable %s=%s", env, val)
	}
}

func NewServer(appName string) *Server {
	verifyEnvVars()
	r := gin.Default()
	/*Create store to manage session cookies (will encrypt them)*/
	sessionName := "authentication"
	logrus.Debugf("Creating session store named %s", sessionName)
	store := cookie.NewStore([]byte("secretForCookieSession"))
	store.Options(sessions.Options{MaxAge: 60 * 60 * 24 * 7, HttpOnly: true, Path: "/"}) // expires in a week
	/*Adding session*/
	/*Adding logger middleware for logger stored in context*/
	r.Use(sessions.Sessions(sessionName, store), logger.Middleware(appName))
	authMiddleware := &auth.Middleware{}
	authController := auth.NewAuthController()
	authController.Handle(r)
	return &Server{
		r,
		authMiddleware,
	}
}

func (gf *Server) Run() error {
	port := os.Getenv("PORT")
	logrus.Infof("Starting server on port %s", port)
	return gf.Engine.Run(":" + port)
}

func GetLoginURL() string {
	oidcHost := os.Getenv("OIDC_HOST")
	externalUrl := os.Getenv("EXTERNAL_URL")
	clientId := os.Getenv("CLIENT_CLIENT_ID")
	codeChallenge := os.Getenv("CODE_CHALLENGE")
	codeChallengeMethod := os.Getenv("CODE_CHALLENGE_METHOD")
	redirectUri := externalUrl + "/auth/callback"
	responseType := "code"
	scope := "openid offline_access email profile role urn:iam:org:project:roles"
	return fmt.Sprintf("%s/oauth/v2/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&code_challenge=%s&code_challenge_method=%s",
		oidcHost, clientId, redirectUri, responseType, scope, codeChallenge, codeChallengeMethod)
}

func (gf *Server) POSTWithAuth(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	handlers = append([]gin.HandlerFunc{gf.AuthMiddleware.Authenticate()}, handlers...)
	return gf.POST(relativePath, handlers...)
}

func (gf *Server) GETWithAuth(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	handlers = append([]gin.HandlerFunc{gf.AuthMiddleware.Authenticate()}, handlers...)
	return gf.GET(relativePath, handlers...)
}

func (gf *Server) DELETEWithAuth(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	handlers = append([]gin.HandlerFunc{gf.AuthMiddleware.Authenticate()}, handlers...)
	return gf.DELETE(relativePath, handlers...)
}

func (gf *Server) PATCHWithAuth(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	handlers = append([]gin.HandlerFunc{gf.AuthMiddleware.Authenticate()}, handlers...)
	return gf.PATCH(relativePath, handlers...)
}

func (gf *Server) PUTWithAuth(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	handlers = append([]gin.HandlerFunc{gf.AuthMiddleware.Authenticate()}, handlers...)
	return gf.PUT(relativePath, handlers...)
}

func (gf *Server) OPTIONSWithAuth(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	handlers = append([]gin.HandlerFunc{gf.AuthMiddleware.Authenticate()}, handlers...)
	return gf.OPTIONS(relativePath, handlers...)
}

func (gf *Server) HEADWithAuth(relativePath string, handlers ...gin.HandlerFunc) gin.IRoutes {
	handlers = append([]gin.HandlerFunc{gf.AuthMiddleware.Authenticate()}, handlers...)
	return gf.HEAD(relativePath, handlers...)
}
