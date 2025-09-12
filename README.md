# IraAuth Client

### Install

```bash
go get github.com/epicira/ira-auth-go@v0.3.0
```

### Configuration
ira-auth.yaml
```yaml
{
  "client_id": "ira_auth_go_example",
  "client_secret": "wmEta4A+vfniXiUTfqwVjQ4/G6HXIqGxHX13jD27pZm7",
  "access_token_name": "my_access_token", # Cookie name for storing access token
  "app_url": "http://127.0.0.1:5678", # Application Base URL
  "redirect_url": "http://127.0.0.1:5678/authenticate/callback",
  "logout_url": "http://127.0.0.1:5678/logout",
  "disable_auth": false
}
```

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
