# IraAuth Client

### Pseudocode example
```go
iraAuth := auth.InitializeIraAuth("ira-auth.yaml")

authenticateHandler := func(r Request) {
    url := iraAuth.GetAuthRedirectURL()
    http.Redirect(http.StatusFound, url)
    return
}

type HttpHandler = func (r Request)

introspectMiddleware := func(iraAuth *IraAuth, httpHandler HttpHandler) HttpHandler {
    return func (r Request) {
        if iraAuth.DisableAuth {
            return httpHandler(r)
        }
        cookie, err := r.GetCookie(iraAuth.AccessTokenName)
        if err != nil {
            return authenticateHandler(r)
        }
        active, err := iraAuth.Introspect(cookie.Value)
        if err != nil {
            return authenticateHandler(r)
        }
        if active {
            return httpHandler(r)
        }
        return authenticateHandler(r)
    }
}

http.GET("/authenticate", authenticateHandler)

http.GET("/authenticate/callback", func (r Request) {
   state := r.FormValue("state")
   code := r.FormValue("code")
   cookies, err := HandleCallback(state, code)
   if err != nil {
       authenticateHandler(r)
   }
   httpResp := http.Response()
   httpResp.SetCookie(cookies.TokenCookie)
   httpResp.SetCookie(cookies.IDCookie)
   httpResp.Redirect(http.StatusMovedPermanently, iraAuth.AppURL)
   return
})
```
