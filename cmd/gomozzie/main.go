package main

/*
#include <mosquitto.h>
#include <mosquitto_plugin.h>
typedef const struct mosquitto const_mosquitto;
typedef const struct mosquitto_acl_msg const_mosquitto_acl_msg;
typedef const char const_char;
typedef struct {
	char *note;
} userdata;
*/
import "C"
import (
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

func initUserdata(opts map[string]string) (unsafe.Pointer, error) {
	data := (*C.userdata)(C.malloc(C.sizeof_userdata))
	(*data).note = C.CString("Shwmae")
	// toDo check options
	return unsafe.Pointer(data), nil
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

	// extract opts
	optMap := extractOptions(opts, opt_count)
	logger.Println(optMap)

	*user_data, err = initUserdata(optMap)
	if err != nil {
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

	data := (*C.userdata)(user_data)
	logger.Printf("Note: %v\n", C.GoString((*data).note))

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
