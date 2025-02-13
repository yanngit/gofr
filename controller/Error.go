package controller

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"sportracker/view"
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
			c.Render(http.StatusInternalServerError, view.TemplRenderer{Component: view.Error("Internal error please try again later ..."), Context: c})
		} else {
			c.Render(http.StatusInternalServerError, view.TemplRenderer{Component: view.Error(fmt.Sprintf("%s: %s", internalError.Message, err.Error())), Context: c})
		}
		c.AbortWithError(http.StatusInternalServerError, err)
	} else if errors.As(err, &authError) {
		if os.Getenv("ENV") == "prod" {
			c.Render(http.StatusUnauthorized, view.TemplRenderer{Component: view.Error("Something wrong happened with your authentication, please login again"), Context: c})
		} else {
			c.Render(http.StatusUnauthorized, view.TemplRenderer{Component: view.Error(fmt.Sprintf("%s: %s", authError.Message, err.Error())), Context: c})
		}
		c.AbortWithError(http.StatusUnauthorized, err)
	}
}
