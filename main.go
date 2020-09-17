package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/jamiealquiza/bicache"
	"golang.org/x/crypto/blake2b"
)

// AccessTokenRequest Request to GitLab to request a token
type AccessTokenRequest struct {
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"` // NB GitLab 10.7.3 has this, but its not documented. See https://gitlab.com/gitlab-org/gitlab/-/issues/21745
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// AccessTokenResponse Response from GitLab when requesting a token
type AccessTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"` // NB GitLab 10.7.3 has this, but its not documented. See https://gitlab.com/gitlab-org/gitlab/-/issues/21745
	Created          int32  `json:"created_at"`
	ExpiresInSeconds int32  `json:"expires_in"` // NB GitLab 10.7.3 does not have this. See https://gitlab.com/gitlab-org/gitlab/-/issues/21745
}

// GetAccessToken see https://docs.gitlab.com/ce/api/oauth2.html#resource-owner-password-credentials
func GetAccessToken(gitLabTokenURL, username, password string) (*AccessTokenResponse, error) {
	requestJSON, err := json.Marshal(&AccessTokenRequest{
		GrantType: "password",
		Scope:     "read_repository read_api",
		Username:  username,
		Password:  password,
	})
	if err != nil {
		return nil, err
	}
	response, err := http.Post(gitLabTokenURL, "application/json", bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, err
	}
	dump, _ := httputil.DumpResponse(response, true)
	log.Printf("AccessToken response %q", dump)
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("invalid response %v", response)
	}

	// If the header is missing, just try to unmarshal it, however, if the content type is provided
	// verify that we got JSON back.
	if ct, ok := response.Header["Content-Type"]; ok &&
		len(ct) > 0 &&
		!strings.HasPrefix(ct[0], "application/json") {

		return nil, fmt.Errorf("invalid Content Type `%s` for response: %v", ct[0], response)
	}
	var accessTokenResponse AccessTokenResponse
	if err := json.Unmarshal(responseBody, &accessTokenResponse); err != nil {
		return nil, err
	}
	return &accessTokenResponse, nil
}

// GetCachedAccessToken Gets the access token from the cache (validated by the user password).
// If not found, then the token is requested through the OAuth interface provided by GitLab.
func GetCachedAccessToken(c *bicache.Bicache, tokenURL, username, password string) ([]byte, error) {
	hp := blake2b.Sum256([]byte(password))
	cv := c.Get(username)
	if cv != nil {
		v := cv.([]byte)
		if !bytes.HasPrefix(v, hp[:]) {
			return nil, fmt.Errorf("invalid password")
		}
		log.Printf("Cache-Hit getting access token for username %s", username)
		return v[len(hp):], nil
	}

	log.Printf("Cache-Miss getting access token for username %s", username)
	response, err := GetAccessToken(tokenURL, username, password)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(response.TokenType) != "bearer" {
		return nil, fmt.Errorf("Unknown access token type: `%s`", response.TokenType)
	}
	t := []byte(response.AccessToken)
	v := append(hp[:], t...)
	var cacheTTL int32
	if response.ExpiresInSeconds > 1 {
		log.Printf("Token TTL for user %s provided by GitLab. TTL : %d", username, response.ExpiresInSeconds)
		cacheTTL = response.ExpiresInSeconds - 1
	} else {
		log.Printf("Token TTL for user %s not provided by GitLab. Using default 3600 seconds.", username)
		cacheTTL = 3600
	}
	c.SetTTL(username, v, cacheTTL)
	return v[len(hp):], nil
}

// ConvertURIToAPI converts a URI for a RAW file to an API call.
// If the URI does not contain the exact text `/raw/`, then the
// original URI is returned. API format for the RAW file is `/api/v4/projects/:id/repository/files/:file_path/raw`
// The `id` parameter is the project ID, while the `file_path` parameter is the URL
// encoded file path of the file to be fetched
func ConvertURIToAPI(orig *url.URL, uri string) *url.URL {
	if !strings.Contains(uri, "/raw/") {
		return orig
	}
	log.Printf("splitting: %s", uri)
	idx := strings.Index(uri, "/-/raw/")
	idxLen:=len("/-/raw/")
	if idx<0{
		idx = strings.Index(uri, "/raw/")
		idxLen=len("/raw/")
	}
	projectName := strings.TrimPrefix(uri[0:idx], "/")
	parts := uri[idx+idxLen:]
	idx = strings.Index(parts, "/")
	if idx < 1 {
		return orig
	}
	ref := parts[0:idx]
	file := parts[idx+1:]

	log.Printf("Project Name: %s", projectName)
	log.Printf("File Name: %s", file)
	log.Printf("Ref: %s", ref)
	path:= fmt.Sprintf("/api/v4/projects/%s/repository/files/%s/raw",
			url.QueryEscape(projectName),
			url.QueryEscape(file),
		)
	// this is needed because GO Urls are stupid.
	tnPath, _ := url.QueryUnescape(path)

	qry:=fmt.Sprintf("ref=%s",
		url.QueryEscape(ref),
	)
	return &url.URL{
		Scheme:   orig.Scheme,
		Host:     orig.Host,
		Path:     tnPath,
		RawPath:  path,
		RawQuery: qry,
	}
}

var (
	listenAddressFlag      = flag.String("listen-address", "127.0.0.1:7000", "HOSTNAME:PORT where this http proxy listens at (e.g. 127.0.0.1:7000)")
	baseGitLabURLFlag      = flag.String("gitlab-base-url", "", "GitLab Base URL (e.g. https://gitlab.example.com/)")
	insecureSkipVerifyFlag = flag.Bool("tls-insecure-skip-verify", false, "Skip GitLab TLS verification")
)

func main() {
	flag.Parse()

	if *baseGitLabURLFlag == "" {
		log.Printf("Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		return
	}

	if *insecureSkipVerifyFlag {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	c, err := bicache.New(&bicache.Config{
		MFUSize:    24,        // MFU capacity in keys
		MRUSize:    64,        // MRU capacity in keys
		ShardCount: 64,        // Shard count. Defaults to 512 if unset.
		AutoEvict:  60 * 1000, // Run TTL evictions + MRU->MFU promotions / evictions automatically every 60s.
		EvictLog:   true,      // Emit eviction timing logs.
		NoOverflow: false,     // Disallow Set ops when the MRU cache is full.
	})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	gitLabBaseURL, err := url.Parse(strings.TrimRight(*baseGitLabURLFlag, "/"))
	if err != nil {
		log.Fatal(err)
	}
	gitLabTokenURL := gitLabBaseURL.String() + "/oauth/token"

	reverseProxy := httputil.NewSingleHostReverseProxy(gitLabBaseURL)
	defaultReverseProxyDirector := reverseProxy.Director
	reverseProxy.Director = func(r *http.Request) {
		defaultReverseProxyDirector(r)
		r.Header.Set("User-Agent", "gitlab-source-link-proxy") // TODO use this user-agent in all this application http requests.
		username, password, ok := r.BasicAuth()
		if !ok {
			log.Print("There is no basic auth in request")
			r.Header.Set("Authorization", "")
			return
		}
		accessToken, err := GetCachedAccessToken(c, gitLabTokenURL, username, password)
		if err != nil {
			log.Printf("Error getting the access token: %v", err)
			r.Header.Set("Authorization", "")
			return
		}
		log.Printf("Using token: %s", accessToken)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		r.URL = ConvertURIToAPI(r.URL, r.RequestURI)
		log.Printf("New Uri: %v", r.URL)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Printf("%q", dump)
		auth := r.Header.Get("Authorization")
		if auth == "" {
			log.Printf("request not authenticated, requesting authentication")
			w.Header().Set("WWW-Authenticate", `Basic realm="GitLab"`)
			w.Header().Set("Cache-Control", `no-cache`)
			http.Error(w, "HTTP Basic: Access denied", 401)
			return
		}
		log.Printf("request has authentication info, proxying request")
		reverseProxy.ServeHTTP(w, r)
	})
	log.Fatal(http.ListenAndServe(*listenAddressFlag, nil))
}
