package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.hrlyit.com/lls-blockchain/go-lib/secrets/shamirSecretSharing"
	"syscall/js"
)

func recoverShares(this js.Value, i []js.Value) interface{} {
	if len(i) != 1 {
		return js.ValueOf(" input value required. Array of recover bytes (base64 encoded strings)")
	}
	if i[0].Type() != js.TypeObject {
		return js.ValueOf("First value must be the Input bytes (base64 encoded string)")
	}
	js.Global().Get("console").Call("log", "recoverShares")
	inStrings := make([]string, i[0].Length())
	for k := 0; k < i[0].Length(); k++ {
		inStrings[k] = i[0].Index(k).String()
		js.Global().Get("console").Call("log", inStrings[k])
		if len(inStrings[k]) == 0 {
			return js.ValueOf(fmt.Sprintf("Please provide all shares. Share '%d' is empty", (k + 1)))
		}

		_, err := hex.DecodeString(inStrings[k])
		if byteErr, ok := err.(hex.InvalidByteError); ok {
			return js.ValueOf(fmt.Sprintf("invalid hex character %q in share", byte(byteErr)))
		}
	}

	key, err := shamirSecretSharing.SharesCombine(inStrings)
	if err != nil {
		return js.ValueOf("Could not combine shares" + err.Error())
	}
	js.Global().Get("console").Call("log", key)
	return js.ValueOf(base64.StdEncoding.EncodeToString([]byte(key)))
}

func distributeShares(this js.Value, i []js.Value) interface{} {
	if len(i) < 3 {
		return js.ValueOf("at least 3 input values required. Input bytes (base64 encoded string), n,k")
	}
	if i[0].Type() != js.TypeString {
		return js.ValueOf("First value must be the Input bytes (base64 encoded string)")
	}

	if i[1].Type() != js.TypeNumber || i[2].Type() != js.TypeNumber {
		return js.ValueOf("n,k must be of type number")
	}

	if i[1].Int() < i[2].Int() {
		return js.ValueOf("k must be smaller or equal to n")
	}

	inBytes, err := base64.StdEncoding.DecodeString(i[0].String())
	if err != nil {
		return js.ValueOf("Could not decode base64 string: " + err.Error())
	}
	js.Global().Get("console").Call("log", fmt.Sprintf("numShares:%d", i[2].Int()))
	js.Global().Get("console").Call("log", fmt.Sprintf("threshold:%d", i[1].Int()))

	shares, err := shamirSecretSharing.GenerateShares(string(inBytes), i[1].Int(), i[2].Int())
	if err != nil {
		return js.ValueOf("Could not distribute string: " + err.Error())
	}

	hexShares := make([]interface{}, len(shares))
	for k, share := range shares {
		hexShares[k] = fmt.Sprintf("%s", share)
	}
	return js.ValueOf(hexShares)
}

func registerCallbacks() {
	js.Global().Set("Distribute_fours", js.FuncOf(distributeShares))
	js.Global().Set("Recover_fours", js.FuncOf(recoverShares))
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("recovered from ", r)
		}
	}()
	c := make(chan struct{}, 0)

	println("WASM Go Initialized")
	// register functions
	registerCallbacks()
	<-c
}
