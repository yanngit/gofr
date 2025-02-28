package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/yanngit/gofr/gofrerr"
)

type Middleware struct {
	jKWS *jWKSet
}

type jWK struct {
	Use string `json:"use"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jWKSet struct {
	Keys []jWK `json:"keys"`
}

type tokenInfo struct {
	Active            bool                         `json:"active"`
	Scope             string                       `json:"scope"`
	ClientId          string                       `json:"client_id"`
	TokenType         string                       `json:"token_type"`
	Exp               int64                        `json:"exp"`
	Iat               int64                        `json:"iat"`
	AuthTime          int64                        `json:"auth_time"`
	Nbf               int64                        `json:"nbf"`
	Sub               string                       `json:"sub"`
	Aud               []string                     `json:"aud"`
	Amr               []string                     `json:"amr"`
	Iss               string                       `json:"iss"`
	Jti               string                       `json:"jti"`
	Username          string                       `json:"username"`
	Name              string                       `json:"name"`
	GivenName         string                       `json:"given_name"`
	FamilyName        string                       `json:"family_name"`
	Locale            string                       `json:"locale"`
	UpdatedAt         int64                        `json:"updated_at"`
	PreferredUsername string                       `json:"preferred_username"`
	Email             string                       `json:"email"`
	EmailVerified     bool                         `json:"email_verified"`
	Roles             map[string]map[string]string `json:"urn:zitadel:iam:org:project:roles"`
}

// Parse a jWK to an RSA public key
func (jwk jWK) toRSAPublicKey() (*rsa.PublicKey, error) {
	// Decode Base64 URL-encoded modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	// Decode Base64 URL-encoded exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}
	// Convert exponent to integer
	var e int
	if len(eBytes) == 3 { // Common for "AQAB" (65537)
		e = int(eBytes[0])<<16 | int(eBytes[1])<<8 | int(eBytes[2])
	} else {
		e = int(eBytes[0])
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// Validate JWT with jWK
func isTokenValidOffline(c *gin.Context, tokenString string, jwkSet *jWKSet) (bool, error) {
	cLogger := c.MustGet("logger").(*logrus.Entry)
	cLogger.Debugf("validating token offline")
	// Extract key ID (kid) from token header
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check if the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Find the matching jWK by "kid"
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing 'kid' header")
		}
		for _, jwk := range jwkSet.Keys {
			if jwk.Kid == kid {
				// Convert jWK to RSA Public Key
				return jwk.toRSAPublicKey()
			}
		}
		return nil, fmt.Errorf("no matching jWK found for kid: %s", kid)
	})
	if err != nil {
		return false, err
	}
	// Check if the token is valid
	if !token.Valid {
		return false, fmt.Errorf("invalid token")
	}
	cLogger.Debug("✅ Token is valid!")
	return true, nil
}

func getTokenInfo(c *gin.Context, token string) (*tokenInfo, error) {
	cLogger := c.MustGet("logger").(*logrus.Entry)
	client := &http.Client{}
	/*Validate token upon OIDC server*/
	oidcHost := os.Getenv("OIDC_HOST")
	oidcServerClientSecret := os.Getenv("SERVER_CLIENT_SECRET")
	oidcServerClientId := os.Getenv("SERVER_CLIENT_ID")
	encodedClientID := url.QueryEscape(oidcServerClientId)
	encodedClientSecret := url.QueryEscape(oidcServerClientSecret)
	credentials := encodedClientID + ":" + encodedClientSecret
	encodedCredentials := base64.StdEncoding.EncodeToString([]byte(credentials))
	authHeader := "Basic " + encodedCredentials
	oidcIntrospectTokenUrl := oidcHost + "/oauth/v2/introspect"
	formData := url.Values{
		"token": {token},
	}
	cLogger.Debugf("getting token info with formData=%+v and url=%s", formData, oidcIntrospectTokenUrl)
	req, err := http.NewRequest(http.MethodPost, oidcIntrospectTokenUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, gofrerr.NewInternalErrorWithMessage(err, "cannot create http request for token introspection")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", authHeader)
	resp, err := client.Do(req)
	if err != nil {
		return nil, gofrerr.NewInternalErrorWithMessage(err, "cannot create http request for token introspection")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, gofrerr.NewInternalErrorWithMessage(err, "cannot read token introspection response")
	}
	/*Unmarshal the JSON response into struct*/
	var introResponse tokenInfo
	err = json.Unmarshal(body, &introResponse)
	if err != nil {
		return nil, gofrerr.NewInternalErrorWithMessage(err, "cannot unmarshall token introspection response")
	}
	return &introResponse, nil
}

func doRefreshToken(c *gin.Context, refreshToken string) error {
	cLogger := c.MustGet("logger").(*logrus.Entry)
	cLogger.Debugf("refreshingToken")
	/*Request a token to OIDC provider to store it on a session for the user so that he can navigate*/
	oidcHost := os.Getenv("OIDC_HOST")
	oidcClientClientId := os.Getenv("CLIENT_CLIENT_ID")
	oidcRefreshTokenUrl := oidcHost + "/oauth/v2/token"
	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken + "toto"},
		"client_id":     {oidcClientClientId},
	}
	err := GetTokenAndSaveDataInSession(c, formData, oidcRefreshTokenUrl)
	if err != nil {
		return gofrerr.NewAuthErrorWithMessage(err, "cannot refresh token")
	}
	return nil
}

func (a *Middleware) getJKWS() error {
	client := &http.Client{}
	/*Request a token to OIDC provider to store it on a session for the user so that he can navigate*/
	oidcHost := os.Getenv("OIDC_HOST")
	oidcKeysUrl := oidcHost + "/oauth/v2/keys"

	req, err := http.NewRequest(http.MethodGet, oidcKeysUrl, nil)
	if err != nil {
		return gofrerr.NewInternalErrorWithMessage(err, "cannot create http request for jKWS")
	}

	resp, err := client.Do(req)
	if err != nil {
		return gofrerr.NewInternalErrorWithMessage(err, "cannot execute http request for jKWS")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return gofrerr.NewInternalErrorWithMessage(err, "cannot read OIDC jKWS response")
	}
	/*Unmarshal the JSON response into struct*/
	err = json.Unmarshal(body, &a.jKWS)
	if err != nil {
		return gofrerr.NewInternalErrorWithMessage(err, "cannot unmarshall OIDC jKWS response")
	}
	return nil
}

func (a *Middleware) Authenticate() gin.HandlerFunc {
	if a.jKWS == nil {
		if err := a.getJKWS(); err != nil {
			panic(fmt.Errorf("cannot get jKWS: %v", err))
		}
	}
	return func(c *gin.Context) {
		cLogger := c.MustGet("logger").(*logrus.Entry)
		session := sessions.Default(c)
		accessToken := session.Get("accessToken")
		if accessToken == nil {
			gofrerr.HandleError(c, gofrerr.NewAuthErrorWithMessage(errors.New("accessToken nil in Authenticate middleware"), "accessToken not defined in the session"))
			return
		}
		/*First we validate the accessToken*/
		tokenValid, err := isTokenValidOffline(c, accessToken.(string), a.jKWS)
		if err != nil {
			gofrerr.HandleError(c, gofrerr.NewAuthErrorWithMessage(err, "not able to validate access token"))
			return
		}
		/*If access token is not active, we try to refresh token*/
		if !tokenValid {
			refreshToken := session.Get("refreshToken")
			if refreshToken == nil {
				gofrerr.HandleError(c, gofrerr.NewAuthErrorWithMessage(errors.New("refreshToken nil"), "refreshToken not defined in the session"))
				return
			}

			cLogger.Infof("token not valid, trying to refresh the token")
			err = doRefreshToken(c, refreshToken.(string))
			if err != nil {
				gofrerr.HandleError(c, err)
				return
			}
			/*Get user info with new access_key*/
			accessToken = session.Get("accessToken")
			tokenInfo, err := getTokenInfo(c, accessToken.(string))
			if err != nil {
				gofrerr.HandleError(c, err)
				return
			}
			if !tokenInfo.Active {
				gofrerr.HandleError(c, gofrerr.NewAuthErrorWithMessage(errors.New("access token expired after refresh"), "access token expired after refresh success"))
				return
			}
		}
		/*Add userEmail in context logger*/
		userEmail := session.Get("email")
		cLogger = cLogger.WithField("userEmail", userEmail)
		c.Set("logger", cLogger)
	}
}
