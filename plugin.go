package main

import (
	"fmt"
	"github.com/limaechocharlie/amrest"
	"net/http"
	"unsafe"
	"encoding/json"
	"strconv"
	"os"
	"time"
	"io/ioutil"
	"strings"
	"io"
	"log"
)

// access describes the type of access to a topic that the client is requesting
type access int

func (a access) String() string {
	switch a {
	case read:
		return "read"
	case write:
		return "write"
	default:
		return "unknown"
	}
}

const (
	read  access = 0x01		// read from a topic
	write access = 0x02		// write to a topic
)

type userData struct {
	// configuration data
	baseURL     string
	realm       string
	cookieName  string
	application string
	client      amrest.User
	admin       amrest.User
	adminRealm  string
	// clientCache to store client data between API calls. The client pointer value is used as the key.
	clientCache map[unsafe.Pointer][]byte
}

func (u userData) String() string {
	return fmt.Sprintf("{ baseURL: %s, realm: %s, cookieName: %s, application: %s, client: %s, admin: %s, adminRealm: %s}",
		u.baseURL, u.realm, u.cookieName, u.application, u.client, u.admin, u.adminRealm)
}

const (
	optPrefix = "openam_"

	optHost           = optPrefix + "host"
	optPort           = optPrefix + "port"
	optPath           = optPrefix + "path"
	optRealm          = optPrefix + "realm"
	optCookieName     = optPrefix + "cookiename"
	optApplication    = optPrefix + "application"
	optClientUsername = optPrefix + "client_id"
	optClientPassword = optPrefix + "client_secret"
	optAgentUsername  = optPrefix + "agent_user"
	optAgentPassword  = optPrefix + "agent_password"
	optAgentRealm     = optPrefix + "agent_realm"
	// optional
	optUseTLS  = optPrefix + "use_tls"
	optLogDest = optPrefix + "log_dest"
)

var requiredOpts = [...]string{
	optHost,
	optPort,
	optPath,
	optRealm,
	optCookieName,
	optApplication,
	optClientUsername,
	optClientPassword,
	optAgentUsername,
	optAgentPassword,
	optAgentRealm,
}

// initialiseUserData initialises the data shared between plugin calls
func initialiseUserData(opts map[string]string) (userData, error) {
	var data userData
	// check all the required options have been supplied
	for _, o := range requiredOpts {
		if _, ok := opts[o]; !ok {
			return data, fmt.Errorf("missing opt %s", o)
		}
	}

	// decide on protocol
	protocol := "http"
	if useTLS, err := strconv.ParseBool(opts[optUseTLS]); err == nil && useTLS {
		protocol = "https"
	}

	// copy over user data values
	data.baseURL = fmt.Sprintf("%s://%s:%s%s", protocol, opts[optHost], opts[optPort], opts[optPath])
	data.realm = opts[optRealm]
	data.cookieName = opts[optCookieName]
	data.application = opts[optApplication]
	data.client.Username = opts[optClientUsername]
	data.client.Password = opts[optClientPassword]
	data.admin.Username = opts[optAgentUsername]
	data.admin.Password = opts[optAgentPassword]
	data.adminRealm = opts[optAgentRealm]

	// make client cache
	data.clientCache = make(map[unsafe.Pointer][]byte)
	return data, nil
}

// initialiseLogger initialises the logger depending on the fields in the supplied configuration string
func initialiseLogger(s string) (l *log.Logger, f *os.File, err error) {
	const (
		destNone   = "none"
		destFile   = "file"
		destStdout = "stdout"
	)
	settings := strings.Fields(s)
	loggingType := destStdout
	if len(settings) > 0 {
		loggingType = settings[0]
	}

	var w io.Writer
	switch loggingType {
	case destFile:
		if len(settings) < 2 {
			return l, f, fmt.Errorf("file path missing")
		}
		var err error
		f, err = os.OpenFile(settings[1], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return l, f, err
		}
		w = f
	case destStdout:
		w = os.Stdout
	case destNone:
		w = ioutil.Discard
	}
	return log.New(w, "AUTH_PLUGIN: ", log.LstdFlags|log.Lshortfile), f, nil
}

// clearUserData clears the userData struct so that memory can be garbage collected
func clearUserData(user *userData)  {
	user.clientCache = nil
}

// doer is an interface that represents a http client
type doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// statusCodeError indicate that an unexpected status code has been returned by the server
type statusCodeError int

func (e statusCodeError) Error() string {
	return fmt.Sprintf("received status code %d", e)
}

// doRequest sends a http request, checking the response for the expected status code and the body
func doRequest( client doer, req *http.Request, expectedStatusCode int) (body []byte, err error) {
	const (
		retryLimit = 4
		backOff    = 100 * time.Millisecond
	)
	f := func(client doer, req *http.Request, expectedStatusCode int)([]byte, error) {
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != expectedStatusCode {
			return body, statusCodeError(resp.StatusCode)
		}
		return body, nil
	}

	for i, b := 0, time.Duration(0); i < retryLimit; i, b = i+1, b+backOff {
		time.Sleep(b) 	// a zero duration will return immediately
		body, err = f(client, req , expectedStatusCode)
		if err == nil {
			break
		}
	}
	return body, err
}

// Checks whether a client is authorised to read from or write to a topic.
func authorise(httpDo doer, user *userData, access access, client unsafe.Pointer, topic string) (bool, error) {
	// get cache data
	cacheTokenInfo, ok := user.clientCache[client]
	if !ok {
		return false, fmt.Errorf("client %p is missing from cache\n", client)
	}
	// toDo utility format function for mqtt resource strings
	amTopic := "mqtt+topic://" + topic
	// toDo check token expiry

	// get SSO token
	authRequest, err := amrest.AuthenticateRequest(user.baseURL, user.adminRealm, user.admin)
	if err != nil {
		return false, fmt.Errorf("failed to create a authenticate request:", err)
	}
	authBytes, err := doRequest(httpDo, authRequest, http.StatusOK)
	if err != nil {
		return false, fmt.Errorf("failed to start a session, %s\n", err)
	}

	var authResponse amrest.AuthenticateResponse
	if err := json.Unmarshal(authBytes, &authResponse); err != nil {
		return false, fmt.Errorf("failed to unmarshal SSO token, %s\n", err)
	}
	ssoToken := authResponse.TokenID

	// evaluate policies
	policies := amrest.NewPolicies([]string{amTopic}, user.application).AddClaims(cacheTokenInfo)
	evalRequest, err := amrest.PoliciesEvaluateRequest(user.baseURL, user.realm, user.cookieName, ssoToken, policies)
	if err != nil {
		return false, fmt.Errorf("failed to create a policies evaluate request:", err)
	}
	evalBytes, err := doRequest(httpDo, evalRequest, http.StatusOK)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate policies, %s\n", err)
	}

	var evaluations []amrest.PolicyEvaluation
	if err := json.Unmarshal(evalBytes, &evaluations); err != nil {
		return false, fmt.Errorf("failed to unmarshal policies, %s\n", err)
	}
	if len(evaluations) != 1 {
		return false, fmt.Errorf("expected only one resource; got %d\n", len(evaluations))
	}
	actions := evaluations[0].Actions

	var b bool
	switch access {
	case read:
		b = actions["RECEIVE"]
	case write:
		b = actions["PUBLISH"]
	default:
		return false, fmt.Errorf("Unexpected access request %d\n", access)
	}
	return b, nil
}

/*
 * authenticate the client by checking the supplied username and password.
 */
func authenticate(httpDo doer, user *userData, client unsafe.Pointer, username, password string) error {
	if username != "_authn_openid_" {
		return fmt.Errorf("unsupported authentication, username = %s\n", username)
	}
	// an OAuth2 ID Token is passed in as the password. Check that it is valid.
	req, err := amrest.OAuth2IDTokenInfoRequest(user.baseURL, user.realm, user.client, password)
	if err != nil {
		return fmt.Errorf("failed to create a OAuth2 ID Token verification request:", err)
	}
	info, err := doRequest(httpDo, req, http.StatusOK)
	if err != nil {
		return fmt.Errorf("OAuth2 ID Token verification failed:", err)
	}
	// add token info to cache
	user.clientCache[client] = info

	return nil
}
