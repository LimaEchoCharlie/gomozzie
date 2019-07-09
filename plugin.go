package main

import (
	"encoding/json"
	"fmt"
	"github.com/limaechocharlie/amrest"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
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
	read  access = 0x01 // read from a topic
	write access = 0x02 // write to a topic
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
			return data, fmt.Errorf("missing field %s", o)
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

const (
	// constants used by the config file to switch log destination
	destNone   = "none"
	destFile   = "file"
	destStdout = "stdout"
)

// initialiseLogger initialises the logger depending on the fields in the supplied configuration string
// Defaults to stdout if the input string is empty or unrecognised.
// Returns an error if logging to a file is requested but fails.
func initialiseLogger(s string) (l *log.Logger, f *os.File, err error) {
	settings := strings.Fields(s)
	var w = ioutil.Discard
	if len(settings) > 0 {
		switch settings[0] {
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
		default:
			fmt.Printf("WARNING: unknown debug setting, %s", settings)
		}
	}
	return log.New(w, "AUTH_PLUGIN: ", log.LstdFlags|log.Lshortfile), f, nil
}

// clearUserData clears the userData struct so that memory can be garbage collected
func clearUserData(user *userData) {
	user.clientCache = nil
}

// doer is an interface that represents a http client
type doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpResponseError indicates that an unexpected response has been returned by the server
type httpResponseError struct {
	response *http.Response
}

func (e httpResponseError) Error() string {
	statusCode := e.response.StatusCode
	if b, err := httputil.DumpResponse(e.response, true); err == nil {
		return string(b)
	}
	return fmt.Sprintf("received status code %d", statusCode)
}

const (
	retryLimit = 4
)

// withBackOff retries the do function with back off until the max retry limit has been reached
func withBackOff(maxRetry int, do func() (bool, *http.Response, error)) (response *http.Response, err error) {
	const backOff    = 100 * time.Millisecond
	retry := true
	for i, b := 0, time.Duration(0); retry && i < maxRetry; i, b = i+1, b+backOff {
		time.Sleep(b) // a zero duration will return immediately
		retry, response, err = do()
	}
	return
}

// checkResponseStatusCode checks the status code of the response and decides whether a retry is required
func checkResponseStatusCode(response *http.Response) (bool, error) {
	switch response.StatusCode {
	case http.StatusOK:
		return false, nil
	case http.StatusInternalServerError, http.StatusServiceUnavailable:
		return true, httpResponseError{response}
	default:
		return false, httpResponseError{response}
	}
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
	response, err := withBackOff(retryLimit, func() (bool, *http.Response, error) {
		request, err := amrest.AuthenticateRequest(user.baseURL, user.adminRealm, user.admin)
		if err != nil {
			return true, nil, fmt.Errorf("failed to create a authenticate request, %s", err)
		}
		response, err := httpDo.Do(request)
		if err != nil {
			return true, response, err
		}
		retry, err := checkResponseStatusCode(response)
		return retry, response, err

	})
	if err != nil {
		return false, fmt.Errorf("admin authenication failed, %s", err)
	}
	defer response.Body.Close()
	authBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var authResponse amrest.AuthenticateResponse
	if err := json.Unmarshal(authBytes, &authResponse); err != nil {
		return false, fmt.Errorf("failed to unmarshal SSO token, %s", err)
	}
	ssoToken := authResponse.TokenID

	// evaluate policies
	response, err = withBackOff(retryLimit, func() (bool, *http.Response, error) {
		policies := amrest.NewPolicies([]string{amTopic}, user.application).AddClaims(cacheTokenInfo)
		request, err := amrest.PoliciesEvaluateRequest(user.baseURL, user.realm, user.cookieName, ssoToken, policies)
		if err != nil {
			return true, nil, fmt.Errorf("failed to create a policies evaluate request, %s", err)
		}
		response, err := httpDo.Do(request)
		if err != nil {
			return true, response, err
		}
		retry, err := checkResponseStatusCode(response)
		return retry, response, err

	})
	if err != nil {
		return false, fmt.Errorf("policy evaluation failed, %s", err)
	}
	defer response.Body.Close()
	evalBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var evaluations []amrest.PolicyEvaluation
	if err := json.Unmarshal(evalBytes, &evaluations); err != nil {
		return false, fmt.Errorf("failed to unmarshal policies, %s", err)
	}
	if len(evaluations) != 1 {
		return false, fmt.Errorf("expected only one resource; got %d", len(evaluations))
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
		return fmt.Errorf("unsupported authentication, username = %s", username)
	}
	response, err := withBackOff(retryLimit, func() (retry bool, response *http.Response, err error) {
		// an OAuth2 ID Token is passed in as the password. Check that it is valid.
		request, err := amrest.OAuth2IDTokenInfoRequest(user.baseURL, user.realm, user.client, password)
		if err != nil {
			err = fmt.Errorf("failed to create a OAuth2 ID Token verification request, %s", err)
			return false, nil, err
		}
		response, err = httpDo.Do(request)
		if err != nil {
			return true, response, err
		}
		retry, err = checkResponseStatusCode(response)
		return retry, response, err
	})
	if err != nil {
		return fmt.Errorf("OAuth2 ID Token verification failed, %s", err)
	}

	defer response.Body.Close()
	info, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	// add token info to cache
	user.clientCache[client] = info

	return nil
}
