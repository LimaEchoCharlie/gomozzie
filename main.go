package main

/*
#include <mosquitto.h>
#include <mosquitto_plugin.h>
typedef const struct mosquitto const_mosquitto;
typedef const struct mosquitto_acl_msg const_mosquitto_acl_msg;
typedef const char const_char;
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"github.com/limaechocharlie/amrest"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unsafe"
	"time"
)

const (
	aclNone      = 0x00
	aclRead      = 0x01
	aclWrite     = 0x02
	aclSubscribe = 0x04
)

var (
	logger *log.Logger
	file   *os.File = nil
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

// cache to store client data between API calls. The client pointer value is used as the key.
var clientCache map[unsafe.Pointer][]byte

// initLogger initialises the logger depending on the fields in the supplied configuration string
func initLogger(s string) error {
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
			return fmt.Errorf("file path missing")
		}
		var err error
		file, err = os.OpenFile(settings[1], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		w = file
	case destStdout:
		w = os.Stdout
	case destNone:
		w = ioutil.Discard
	}
	logger = log.New(w, "AUTH_PLUGIN: ", log.LstdFlags|log.Lshortfile)
	return nil
}

// initUserData initialises the data shared between plugin calls
func initUserData(opts map[string]string) (unsafe.Pointer, error) {
	var data userData
	// check all the required options have been supplied
	for _, o := range requiredOpts {
		if _, ok := opts[o]; !ok {
			return nil, fmt.Errorf("missing opt %s", o)
		}
	}

	if err := initLogger(opts[optLogDest]); err != nil {
		fmt.Printf("error initialising logger, %s", err)
	}
	logger.Println("Init plugin")

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
	logger.Println(data)
	return unsafe.Pointer(&data), nil
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

//export mosquitto_auth_plugin_version
/*
 * Returns the value of MOSQ_AUTH_PLUGIN_VERSION defined in the mosquitto header file that the plugin was compiled
 * against.
 */
func mosquitto_auth_plugin_version() C.int {
	return C.MOSQ_AUTH_PLUGIN_VERSION
}

//export mosquitto_auth_plugin_init
/*
 * Initialises the plugin.
 */
func mosquitto_auth_plugin_init(cUserData *unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int) C.int {
	var err error
	// copy opts from the C world into Go
	optMap := extractOptions(cOpts, cOptCount)
	// initialise the user data that will be used in subsequent plugin calls
	*cUserData, err = initUserData(optMap)
	if err != nil {
		logger.Println("initUserData failed with err:", err)
		return C.MOSQ_ERR_AUTH
	}
	// make client cache
	clientCache = make(map[unsafe.Pointer][]byte)
	logger.Println("leave - plugin init successful")
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_plugin_cleanup
/*
 * Cleans up the plugin before the server shuts down.
 */
func mosquitto_auth_plugin_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int) C.int {
	logger.Println("enter - plugin cleanup")
	// close logfile
	if file != nil {
		file.Close()
		file = nil
	}
	// set the client cache to nil so it can be garage collected
	clientCache = nil
	logger.Println("leave - plugin cleanup")
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_acl_check
/*
 * Checks whether a client is authorised to read from or write to a topic.
 */
func mosquitto_auth_acl_check(cUserData unsafe.Pointer, cAccess C.int, cClient *C.const_mosquitto, cMsg *C.const_mosquitto_acl_msg) C.int {
	logger.Println("enter - acl check")
	if cUserData == nil {
		logger.Println("Missing cUserData")
		return C.MOSQ_ERR_AUTH
	}

	data := (*userData)(cUserData)
	// get cache data
	cacheTokenInfo, ok := clientCache[unsafe.Pointer(cClient)]
	if !ok {
		logger.Printf("client %p is missing from cache\n", unsafe.Pointer(cClient))
		return C.MOSQ_ERR_AUTH
	}
	// toDo utility format function for mqtt resource strings
	topic := "mqtt+topic://" + C.GoString(cMsg.topic)
	// toDo check token expiry

	// get SSO token
	authRequest, err := amrest.AuthenticateRequest(data.baseURL, data.adminRealm, data.admin)
	if err != nil {
		logger.Println("failed to create a authenticate request:", err)
		return C.MOSQ_ERR_AUTH
	}
	authBytes, err := doRequest(http.DefaultClient, authRequest, http.StatusOK)
	if err != nil {
		logger.Printf("failed to start a session, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}

	var authResponse amrest.AuthenticateResponse
	if err := json.Unmarshal(authBytes, &authResponse); err != nil {
		logger.Printf("failed to unmarshal SSO token, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}
	ssoToken := authResponse.TokenID

	// evaluate policies
	policies := amrest.NewPolicies([]string{topic}, data.application).AddClaims(cacheTokenInfo)
	evalRequest, err := amrest.PoliciesEvaluateRequest(data.baseURL, data.realm, data.cookieName, ssoToken, policies)
	if err != nil {
		logger.Println("failed to create a policies evaluate request:", err)
		return C.MOSQ_ERR_AUTH
	}
	evalBytes, err := doRequest(http.DefaultClient, evalRequest, http.StatusOK)
	if err != nil {
		logger.Printf("failed to evaluate policies, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}

	var evaluations []amrest.PolicyEvaluation
	if err := json.Unmarshal(evalBytes, &evaluations); err != nil {
		logger.Printf("failed to unmarshal policies, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}
	if len(evaluations) != 1 {
		logger.Printf("expected only one resource; got %d\n", len(evaluations))
		return C.MOSQ_ERR_AUTH
	}
	actions := evaluations[0].Actions
	logger.Printf("actions %s\n", actions)

	var b bool
	switch a := int(cAccess); a {
	case aclRead:
		logger.Printf("read")
		b = actions["RECEIVE"]
	case aclWrite:
		logger.Printf("write")
		b = actions["PUBLISH"]
	default:
		logger.Printf("Unexpected access request %d\n", a)
	}
	if !b {
		logger.Println("leave - acl check access denied")
		return C.MOSQ_ERR_PLUGIN_DEFER
	}

	logger.Println("leave - acl check access granted")
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_unpwd_check
/*
 * Authenticates the client by checking the supplied username and password.
 */
func mosquitto_auth_unpwd_check(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cUsername, cPassword *C.const_char) C.int {
	logger.Println("enter - unpwd check")
	if cUsername == nil || cPassword == nil {
		return C.MOSQ_ERR_AUTH
	}

	data := (*userData)(cUserData)
	username := goStringFromConstant(cUsername)
	password := goStringFromConstant(cPassword)
	logger.Printf("u: %s, p: %s\n", username, password)
	if username != "_authn_openid_" {
		logger.Printf("unsupported authentication, username = %s\n", username)
		return C.MOSQ_ERR_AUTH
	}
	// an OAuth2 ID Token is passed in as the password. Check that it is valid.
	req, err := amrest.OAuth2IDTokenInfoRequest(data.baseURL, data.realm, data.client, password)
	if err != nil {
		logger.Println("failed to create a OAuth2 ID Token verification request:", err)
		return C.MOSQ_ERR_AUTH
	}
	info, err := doRequest(http.DefaultClient, req, http.StatusOK)
	if err != nil {
		logger.Println("OAuth2 ID Token verification failed:", err)
		return C.MOSQ_ERR_AUTH
	}

	// add token info to cache
	clientCache[unsafe.Pointer(cClient)] = info

	logger.Println("leave - unpwd check successful")
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_security_init
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_security_init(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_security_cleanup
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_security_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_psk_key_get
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_psk_key_get(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cHint, cIdentity *C.const_char, cKey *C.char, cMaxKeyLen C.int) C.int {
	return C.MOSQ_ERR_SUCCESS
}

func main() {

}
