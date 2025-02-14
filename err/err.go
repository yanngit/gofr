package err

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/yanngit/gofr/renderer"
	"net/http"
	"os"
)

type InternalError struct {
	error
	Message string `json:"message"`
}

type AuthError struct {
	error
	Message string `json:"message"`
}

func NewInternalErrorWithMessage(error error, message string) *InternalError {
	return &InternalError{error: error, Message: message}
}

func NewAuthErrorWithMessage(error error, message string) *AuthError {
	return &AuthError{error: error, Message: message}
}

func NewAuthError(error error) *AuthError {
	return &AuthError{error: error}
}

func HandleError(c *gin.Context, err error) {
	var internalError *InternalError
	var authError *AuthError
	if errors.As(err, &internalError) {
		if os.Getenv("ENV") == "prod" {
			c.Render(http.StatusInternalServerError, renderer.Templ{Component: Error("Internal err please try again later ..."), Context: c})
		} else {
			c.Render(http.StatusInternalServerError, renderer.Templ{Component: Error(fmt.Sprintf("%s: %s", internalError.Message, err.Error())), Context: c})
		}
		c.AbortWithError(http.StatusInternalServerError, err)
	} else if errors.As(err, &authError) {
		if os.Getenv("ENV") == "prod" {
			c.Render(http.StatusUnauthorized, renderer.Templ{Component: Error("Something wrong happened with your authentication, please login again"), Context: c})
		} else {
			c.Render(http.StatusUnauthorized, renderer.Templ{Component: Error(fmt.Sprintf("%s: %s", authError.Message, err.Error())), Context: c})
		}
		c.AbortWithError(http.StatusUnauthorized, err)
	}
}
