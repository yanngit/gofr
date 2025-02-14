package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	error2 "github.com/yanngit/gofr/err"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type AuthController struct {
}

func NewAuthController() *AuthController {
	return &AuthController{}
}

func (ctrl *AuthController) Handle(r *gin.Engine) {
	r.GET("/auth/callback", func(c *gin.Context) {
		cLogger := c.MustGet("logger").(*logrus.Entry)
		/*OIDC provider send us the code after the user log in, thanks to redirect_uri*/
		code := c.Query("code")
		cLogger.Debugf("login callback called for OIDC with code=%s", code)
		/*Request a token to OIDC provider to store it on a session for the user so that he can navigate*/
		oidcHost := os.Getenv("OIDC_HOST")
		oidcClientClientId := os.Getenv("CLIENT_CLIENT_ID")
		codeVerifier := os.Getenv("CODE_VERIFIER")
		externalUrl := os.Getenv("EXTERNAL_URL")
		oidcGetTokenUrl := oidcHost + "/oauth/v2/token"
		formData := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {externalUrl + "/auth/callback"},
			"client_id":     {oidcClientClientId},
			"code_verifier": {codeVerifier},
			"scope":         {"openid profile email offline_access role"},
		}
		err := GetTokenAndSaveDataInSession(c, formData, oidcGetTokenUrl)
		if err != nil {
			error2.HandleError(c, err)
			return
		}
		cLogger.Info("login callback success, redirecting to /home")
		c.Redirect(http.StatusFound, "/home")
	})
}

func GetTokenAndSaveDataInSession(c *gin.Context, formData url.Values, oidcGetTokenUrl string) error {
	cLogger := c.MustGet("logger").(*logrus.Entry)
	client := &http.Client{}
	cLogger.Debugf("requesting token with formData=%+v", formData)
	req, err := http.NewRequest(http.MethodPost, oidcGetTokenUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return error2.NewInternalErrorWithMessage(err, "cannot create http request for OIDC token response")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return error2.NewInternalErrorWithMessage(err, "cannot run http request for OIDC token response")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return error2.NewInternalErrorWithMessage(err, "cannot read OIDC token response")
	}
	/*Unmarshal the JSON response into struct*/
	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return error2.NewInternalErrorWithMessage(err, "cannot unmarshall OIDC token response")
	}
	cLogger.Debugf("token response=%+v", tokenResp)
	if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" {
		return error2.NewAuthError(errors.New(fmt.Sprintf("empty token response: %s", string(body))))
	}
	tokenInfo, err := getTokenInfo(c, tokenResp.AccessToken)
	if err != nil {
		return err
	}
	session := sessions.Default(c)
	session.Set("accessToken", tokenResp.AccessToken)
	session.Set("refreshToken", tokenResp.RefreshToken)
	session.Set("username", tokenInfo.Username)
	session.Set("name", tokenInfo.Username)
	session.Set("familyName", tokenInfo.FamilyName)
	session.Set("Locale", tokenInfo.Locale)
	session.Set("email", tokenInfo.Email)
	session.Set("emailVerified", tokenInfo.EmailVerified)
	if tokenInfo.Roles != nil && tokenInfo.Roles["admin"] != nil {
		session.Set("isAdmin", true)
	} else {
		session.Set("isAdmin", false)
	}
	err = session.Save()
	if err != nil {
		return error2.NewInternalErrorWithMessage(err, "cannot save session with OIDC info")
	}
	return nil
}
