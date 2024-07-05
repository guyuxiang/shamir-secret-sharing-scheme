package shamirSecretSharing

import (
	"errors"
	"github.com/dop251/goja"
	"strings"
)

// 生成分片
func GenerateShares(secret string, numShares int, threshold int) ([]string, error) {
	for {
		got, err := shares(secret, numShares, threshold)
		if err != nil {
			return nil, err
		}

		key, err := combine(got)
		if err != nil {
			continue
		}

		if !strings.Contains(key, secret) {
			continue
		}

		return got, nil
	}
	return nil, errors.New("Generate Shares failed")
}

func shares(secret string, numShares int, threshold int) ([]string, error) {
	vm := goja.New()
	_, err := vm.RunString(SecretScript)
	if err != nil {
		return nil, errors.New("SecretScript err: " + err.Error())
	}

	var str2hex func(string, int) string

	err = vm.ExportTo(vm.Get("str2hex"), &str2hex)
	if err != nil {
		return nil, errors.New("SecretScript str2hex function err: " + err.Error())
	}

	var share func(string, int, int, int) []string

	err = vm.ExportTo(vm.Get("share"), &share)
	if err != nil {
		return nil, errors.New("SecretScript share function err: " + err.Error())
	}

	secret = str2hex(secret, 0)
	padLength := 128
	shares := share(secret, numShares, threshold, padLength)
	return shares, nil
}

// 分片合并
func SharesCombine(shares []string) (string, error) {
	key, err := combine(shares)
	if err != nil {
		return "", err
	}

	return removeNonPrintable(key), nil
}

func combine(shares []string) (string, error) {
	vm := goja.New()
	_, err := vm.RunString(SecretScript)
	if err != nil {
		return "", errors.New("SecretScript err: " + err.Error())
	}

	var hex2str func(string, int) string

	err = vm.ExportTo(vm.Get("hex2str"), &hex2str)
	if err != nil {
		return "", errors.New("SecretScript hex2str function err: " + err.Error())
	}

	var combine func(int, []string) string

	err = vm.ExportTo(vm.Get("combine"), &combine)
	if err != nil {
		return "", errors.New("SecretScript combine function err: " + err.Error())
	}

	key := combine(0, shares)

	str := hex2str(key, 0)

	return str, nil
}

// 去除不可见字符
func removeNonPrintable(str string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1 // -1 means drop the character
	}, str)
}
