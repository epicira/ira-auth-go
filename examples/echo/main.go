package main

import (
	"log"
	"net/http"

	IraAuth "github.com/epicira/ira-auth-go"
	"github.com/labstack/echo/v4"
)

func buildAuthenticateHandler(iraAuth *IraAuth.IraAuth) echo.HandlerFunc {
	return func(c echo.Context) error {
		url := iraAuth.GetAuthRedirectURL()
		return c.Redirect(http.StatusFound, url)
	}
}

func buildIntrospectMiddleware(iraAuth *IraAuth.IraAuth, authenticateHandler echo.HandlerFunc) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if iraAuth.DisableAuth {
				return next(c)
			}
			cookie, err := c.Request().Cookie(iraAuth.AccessTokenName)
			if err != nil {
				log.Printf("could not obtain access token cookie: %s", err)
				return authenticateHandler(c)
			}
			active, err := iraAuth.Introspect(cookie.Value)
			if err != nil {
				log.Printf("token introspection failed: %s", err)
				return authenticateHandler(c)
			}
			if active {
				return next(c)
			}
			return authenticateHandler(c)
		}
	}
}

func main() {
	iraAuth, err := IraAuth.InitializeIraAuth("ira-auth.yaml")
	if err != nil {
		log.Fatalf("could not initialize IraAuth client: %s", err)
	}

	authenticateHandler := buildAuthenticateHandler(iraAuth)
	introspectMiddleware := buildIntrospectMiddleware(iraAuth, authenticateHandler)

	e := echo.New()

	e.GET("/authenticate", authenticateHandler)
	e.GET("/authenticate/callback", func(c echo.Context) error {
		state := c.QueryParam("state")
		code := c.QueryParam("code")

		cookies, err := iraAuth.HandleCallback(state, code)
		if err != nil {
			log.Printf("handle callback error: %s", err)
			return authenticateHandler(c)
		}
		c.SetCookie(cookies.TokenCookie)
		c.SetCookie(cookies.IDCookie)
		return c.Redirect(http.StatusMovedPermanently, iraAuth.AppURL)
	})

	protected := e.Group("/")
	protected.Use(introspectMiddleware)

	protected.File("", "index.html")

	e.Logger.Fatal(e.StartTLS("127.0.0.1:5678", "certs/domain.crt", "certs/domain.key"))
}
