package main

/*
#include <mosquitto_plugin.h>
struct mosquitto_opt* accessArray( struct mosquitto_opt* arrptr, int i)
{
	return arrptr + i;
}
*/
import "C"

// Using //export in a file places a restriction on the preamble: it must not contain any definitions, only declarations.

func extractOptions(arrptr *C.struct_mosquitto_opt, length C.int) map[string]string {
	opts := make(map[string]string, length)
	var i C.int
	for i = 0; i < length; i++ {
		c_opt := C.accessArray(arrptr, i)
		opts[C.GoString(c_opt.key)] = C.GoString(c_opt.value)
	}
	return opts
}
