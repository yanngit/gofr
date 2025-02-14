# gofr
## Base go framework to work with templ and zitadel
The framework is a wrapper around gin to integrate with zitadel and manage authentication.
## How to use it
Get the framework with : 
```bash
go get github.com/yanngit/gofr
```
The framework is expecting env vars to fetch the configuration. We're going to describe how to configure Zitadel 
and how to set expected env vars in this file.
### Run zitadel docker compose
Run zitadel locally with docker compose: https://zitadel.com/docs/self-hosting/deploy/compose
This will run Zitadel locally on `http://localhost:8080/ui/console/`.
Default admin user is `zitadel-admin@zitadel.localhost` and password is `Password1!` that you will change on first login.
### Configure zitadel
Login to the console and create a new project. Tick `Assert Roles on Authentication` on your project config to get roles in
context and create an admin role that you can set to admin users. The role is created in `Roles` menu and 
adding this role to users is done in `Authorizations` menu. Only `admin` role is handled for now, with a boolean set in context.
We're going to create two applications inside it.
#### Client side
Client side application is responsible to get request token and refresh token. Create a web application
with **PKCE authent**, and enter correct redirect URIs. In development, it will be:
- redirect : http://localhost:PORT/auth/callback
- post logout: http://localhost:PORT
For the moment we don't use logout redirect.
Once created, copy client_id and put it as environment variable `CLIENT_CLIENT_ID`.
Edit token settings for the client and set `Auth Token Type` to JWT.
This is required because the framework is doing offline validation.
#### Server side
Server side application is responsible to validate tokens. Create an API application with Basic authentication
and make sure to copy client secret and put it as environment variable `SERVER_CLIENT_SECRET`.
Once created, copy client_id and put it as environment variable `SERVER_CLIENT_ID`.
### Finish OIDC config
Once this is done, add the following env vars:
- OIDC_HOST : URL to reach OIDC server (http://localhost:8080 in dev)
- CODE_VERIFIER : A random string that will be code verifier
- CODE_CHALLENGE : the SHA-256 value in base64 of CODE_VERIFIER (use https://zitadel.com/oidc-playground to generate it)
- CODE_CHALLENGE_METHOD : S256 by default
### Global configuration
Add the following env vars:
- ENV: dev or prod
- PORT: the port to run server on
- EXTERNAL_URL: external URL to reach the app (http://localhost:8085 in dev if PORT is 8085, other DNS if behind nginx proxy)
### Code integration
Now everything is configured, you can create in your project the server : 
```go 
	r := gofr.NewServer("myApp")
```
Where myApp is the name of your app (used for log parsing). 
You can create some routes with or without authentication : 
```go
func (ctrl *BaseController) Handle(r *gofr.Server) {
	r.GET("/", func(c *gin.Context) {
		c.Render(http.StatusOK, renderer.Templ{Component: view.Landing(gofr.GetLoginURL()), Context: c})
	})
	r.GETWithAuth("/home", func(c *gin.Context) {
		session := sessions.Default(c)
		isAdmin := session.Get("isAdmin").(bool)
		name := session.Get("username").(string)
		role := "user"
		if isAdmin {
			role = "admin"
		}
		c.Render(http.StatusOK, renderer.Templ{Component: view.Home(role + " " + name), Context: c})
	})
}
```
Where `gofr.GetLoginURL()` is getting the URL to login, r.GET the same as you would expect from Gin and 
r.GETWithAuth a wrapper to add authentication to your route. The framework will set various session info that 
you can get once authenticated:
- accessToken: string
- refreshToken: string
- username: string
- name: string
- familyName: string
- Locale: string
- email: string
- emailVerified: bool
- admin: bool

Then you can finally run the server : 
```bash 
    err = r.Run()
	if err != nil {
		panic(fmt.Sprintf("cannot run server: %v", err))
	}
```