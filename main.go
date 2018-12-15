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
	"log"
	"net/http"
	"os"
	"unsafe"
)

const (
	success = 0
	failure = 1

	aclNone      = 0x00
	aclRead      = 0x01
	aclWrite     = 0x02
	aclSubscribe = 0x04
)

var (
	logger  *log.Logger
	logFile *os.File
)

type userData struct {
	// configuration data
	baseURL     string
	realm       string
	cookie      string
	application string
	client      amrest.User
	admin       amrest.User
	adminRealm  string
	// cache
	cacheTokenInfo []byte
}

func (u userData) String() string {
	return fmt.Sprintf("{ baseURL: %s, realm: %s, cookieName: %s, application: %s, client: %s, admin: %s, adminRealm: %s}",
		u.baseURL, u.realm, u.cookie, u.application, u.client, u.admin, u.adminRealm)
}

const (
	optPrefix = "openam_"

	optHost           = optPrefix + "host"
	optPort           = optPrefix + "port"
	optPath           = optPrefix + "path"
	optRealm          = optPrefix + "realm"
	optCookie         = optPrefix + "cookiename"
	optApplication    = optPrefix + "application"
	optClientUsername = optPrefix + "client_id"
	optClientPassword = optPrefix + "client_secret"
	optAgentUsername  = optPrefix + "agent_user"
	optAgentPassword  = optPrefix + "agent_password"
	optAgentRealm     = optPrefix + "agent_realm"
)

var requiredOpts = [...]string{
	optHost,
	optPort,
	optPath,
	optRealm,
	optCookie,
	optApplication,
	optClientUsername,
	optClientPassword,
	optAgentUsername,
	optAgentPassword,
	optAgentRealm,
}

func initUserData(opts map[string]string) (unsafe.Pointer, error) {
	var data userData
	// check all the required options have been supplied
	for _, o := range requiredOpts {
		if _, ok := opts[o]; !ok {
			return nil, fmt.Errorf("missing opt %s", o)
		}
	}

	// copy over user data values
	data.baseURL = fmt.Sprintf("%s:%s%s", opts[optHost], opts[optPort], opts[optPath])
	data.realm = opts[optRealm]
	data.cookie = opts[optCookie]
	data.application = opts[optApplication]
	data.client.Username = opts[optClientUsername]
	data.client.Password = opts[optClientPassword]
	data.admin.Username = opts[optAgentUsername]
	data.admin.Password = opts[optAgentPassword]
	data.adminRealm = opts[optAgentRealm]
	logger.Println(data)
	return unsafe.Pointer(&data), nil
}

//export mosquitto_auth_plugin_version
func mosquitto_auth_plugin_version() C.int {
	return C.MOSQ_AUTH_PLUGIN_VERSION
}

//export mosquitto_auth_plugin_init
func mosquitto_auth_plugin_init(cUserData *unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int) C.int {
	var err error
	logFile, err = os.OpenFile("auth.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
		return failure
	}
	logger = log.New(logFile, "AUTH_PLUGIN: ", log.Ldate|log.Lmicroseconds)
	logger.Println("Init plugin")

	// copy opts from the C world into Go
	optMap := extractOptions(cOpts, cOptCount)
	// initialise the user data that will be used in subsequent plugin calls
	*cUserData, err = initUserData(optMap)
	if err != nil {
		logger.Println("initUserData failed with err:", err)
		return failure
	}
	return success
}

//export mosquitto_auth_plugin_cleanup
func mosquitto_auth_plugin_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int) C.int {
	logger.Println("Enter: Plugin cleanup")
	return success
}

//export mosquitto_auth_security_init
func mosquitto_auth_security_init(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	logger.Println("Enter: security init")
	return success
}

//export mosquitto_auth_security_cleanup
func mosquitto_auth_security_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	logger.Println("Enter: security cleanup")
	return success
}

//export mosquitto_auth_acl_check
func mosquitto_auth_acl_check(cUserData unsafe.Pointer, cAccess C.int, cClient *C.const_mosquitto, cMsg *C.const_mosquitto_acl_msg) C.int {
	logger.Println("Enter: acl check")
	if cUserData == nil {
		logger.Println("Missing cUserData")
		return failure
	}

	data := (*userData)(cUserData)
	// toDo utility format function for mqtt resource strings
	topic := "mqtt+topic://" + C.GoString(cMsg.topic)
	// toDo check token expiry

	// get SSO token
	authBytes, err := amrest.Authenticate(http.DefaultClient, data.baseURL, data.adminRealm, data.admin, logger)
	if err != nil {
		logger.Printf("failed to start a session, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}
	authResult := struct {
		TokenID string `json:"tokenId"`
	}{}
	if err := json.Unmarshal(authBytes, &authResult); err != nil {
		logger.Printf("failed to unmarshal SSO token, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}
	ssoToken := authResult.TokenID

	// evaluate policies
	evalBytes, err := amrest.PoliciesEvaluate(http.DefaultClient, data.baseURL, data.realm, data.application, data.cookie, ssoToken,
		data.cacheTokenInfo, []string{topic}, logger)
	if err != nil {
		logger.Printf("failed to evaluate policies, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}
	var evaluation []struct {
		Actions amrest.Actions
	}

	if err := json.Unmarshal(evalBytes, &evaluation); err != nil {
		logger.Printf("failed to unmarhal policies, %s\n", err)
		return C.MOSQ_ERR_AUTH
	}
	if len(evaluation) != 1 {
		logger.Printf("expected only one resource; got %d\n", len(evaluation))
		return C.MOSQ_ERR_AUTH
	}
	actions := evaluation[0].Actions
	logger.Printf("actions %s\n", actions)

	var b bool
	switch a := int(cAccess); a {
	case aclRead:
		b = actions["RECEIVE"]
	case aclWrite:
		b = actions["PUBLISH"]
	default:
		logger.Printf("Unexpected access request %d", a)
	}
	if !b {
		logger.Printf("Access denied")
		return C.MOSQ_ERR_PLUGIN_DEFER
	}

	logger.Printf("Access granted")
	return C.MOSQ_ERR_SUCCESS
}

func goStringFromConstant(cstr *C.const_char) string {
	return C.GoString((*C.char)(cstr))
}

//export mosquitto_auth_unpwd_check
func mosquitto_auth_unpwd_check(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cUsername, cPassword *C.const_char) C.int {
	logger.Println("Enter: unpwd check")
	if cUsername == nil || cPassword == nil {
		return C.MOSQ_ERR_AUTH
	}

	data := (*userData)(cUserData)
	username := goStringFromConstant(cUsername)
	password := goStringFromConstant(cPassword)
	logger.Printf("u: %s, p: %s\n", username, password)
	if username != "_authn_openid_" {
		logger.Printf("Unsupported authentication, username = %s\n", username)
		return C.MOSQ_ERR_AUTH
	}
	// an OAuth2 ID Token is passed in as the password
	info, err := amrest.OAuth2IDTokenInfo(http.DefaultClient, data.baseURL, data.realm, data.client, password, logger)
	if err != nil {
		logger.Println("OAuth2 ID Token verification failed:", err)
		return C.MOSQ_ERR_AUTH
	}
	data.cacheTokenInfo = info
	logger.Println("Leave: unpwd check successful")
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_psk_key_get
func mosquitto_auth_psk_key_get(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cHint, cIdentity *C.const_char, cKey *C.char, cMaxKeyLen C.int) C.int {
	logger.Println("Enter: psk key get")
	return C.MOSQ_ERR_SUCCESS
}

func main() {

}
