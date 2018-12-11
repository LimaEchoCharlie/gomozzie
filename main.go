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
	"fmt"
	"github.com/limaechocharlie/amrest"
	"log"
	"os"
	"unsafe"
)

const (
	success = 0
	failure = 1
)

var (
	logger  *log.Logger
	logFile *os.File
)

type userData struct {
	baseURL     string
	realm       string
	cookie      string
	application string
	client      amrest.User
	admin       amrest.User
}

func (u userData) String() string {
	return fmt.Sprintf("{ baseURL: %s, realm: %s, cookieName: %s, application: %s, client: %s, admin: %s}",
		u.baseURL, u.realm, u.cookie, u.application, u.client, u.admin)
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
	logger.Println(data)
	return unsafe.Pointer(&data), nil
}

//export mosquitto_auth_plugin_version
func mosquitto_auth_plugin_version() C.int {
	return C.MOSQ_AUTH_PLUGIN_VERSION
}

//export mosquitto_auth_plugin_init
func mosquitto_auth_plugin_init(user_data *unsafe.Pointer, opts *C.struct_mosquitto_opt, opt_count C.int) C.int {
	var err error
	logFile, err = os.OpenFile("auth.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
		return failure
	}
	logger = log.New(logFile, "AUTH_PLUGIN: ", log.Ldate|log.Lmicroseconds)
	logger.Println("Init plugin")

	// copy opts from the C world into Go
	optMap := extractOptions(opts, opt_count)
	// initialise the user data that will be used in subsequent plugin calls
	*user_data, err = initUserData(optMap)
	if err != nil {
		logger.Println("initUserData failed with err:", err)
		return failure
	}
	return success
}

//export mosquitto_auth_plugin_cleanup
func mosquitto_auth_plugin_cleanup(user_data unsafe.Pointer, opts *C.struct_mosquitto_opt, opt_count C.int) C.int {
	logger.Println("Enter: Plugin cleanup")
	return success
}

//export mosquitto_auth_security_init
func mosquitto_auth_security_init(user_data unsafe.Pointer, opts *C.struct_mosquitto_opt, opt_count C.int, reload C.bool) C.int {
	logger.Println("Enter: security init")
	return success
}

//export mosquitto_auth_security_cleanup
func mosquitto_auth_security_cleanup(user_data unsafe.Pointer, opts *C.struct_mosquitto_opt, opt_count C.int, reload C.bool) C.int {
	logger.Println("Enter: security cleanup")
	return success
}

//export mosquitto_auth_acl_check
func mosquitto_auth_acl_check(user_data unsafe.Pointer, access C.int, client *C.const_mosquitto, msg *C.const_mosquitto_acl_msg) C.int {
	logger.Println("Enter: acl check")
	if user_data == nil {
		logger.Println("Missing user_data")
		return failure
	}

	data := (*userData)(user_data)
	logger.Printf("Received user data: %v\n", data)

	gaccess := int(access)
	topic := C.GoString(msg.topic)
	payload := C.GoBytes(msg.payload, C.int(msg.payloadlen))
	qos := int(msg.qos)
	retain := bool(msg.retain)
	logger.Printf("a: %d, t: %s, pl: %s, qos: %d, r: %v\n", gaccess, topic, payload, qos, retain)
	return C.MOSQ_ERR_SUCCESS
}

func goStringFromConstant(cstr *C.const_char) string {
	return C.GoString((*C.char)(cstr))
}

//export mosquitto_auth_unpwd_check
func mosquitto_auth_unpwd_check(user_data unsafe.Pointer, client *C.const_mosquitto, username, password *C.const_char) C.int {
	logger.Println("Enter: unpwd check")
	if username == nil || password == nil {
		return C.MOSQ_ERR_AUTH
	}

	gusername := goStringFromConstant(username)
	gpassword := goStringFromConstant(password)
	logger.Printf("u: %s, p: %s\n", gusername, gpassword)
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_psk_key_get
func mosquitto_auth_psk_key_get(user_data unsafe.Pointer, client *C.const_mosquitto, hint, idnetity *C.const_char, key *C.char, max_key_len C.int) C.int {
	logger.Println("Enter: psk key get")
	return C.MOSQ_ERR_SUCCESS
}

func main() {

}
