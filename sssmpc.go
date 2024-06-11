package mpcsss

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// GenerateShares generates n shares with a threshold of m to reconstruct the secret.
func GenerateShares(secret *big.Int, m, n int) ([]*big.Int, error) {
	coeffs := make([]*big.Int, m)
	coeffs[0] = new(big.Int).Set(secret) // Constant term is the secret
	for i := 1; i < m; i++ {
		coeffs[i], _ = rand.Int(rand.Reader, secret) // Random coefficients
	}

	shares := make([]*big.Int, n)
	xValues := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		xValues[i] = x
		shares[i] = evalPolynomial(coeffs, x)
	}

	for i, _ := range shares {
		shareBytes := shares[i].Bytes()
		shareBytes = append(shareBytes, xValues[i].Bytes()[0])
		fmt.Println("shareBytes: ", shareBytes)
		tmp := new(big.Int)
		tmp.SetBytes(shareBytes)
		shares[i] = tmp
	}
	return shares, nil
}

// evalPolynomial evaluates a polynomial with given coefficients at point x.
func evalPolynomial(coeffs []*big.Int, x *big.Int) *big.Int {
	y := big.NewInt(0)
	xi := big.NewInt(1)
	for _, coeff := range coeffs {
		term := new(big.Int).Mul(coeff, xi)
		y.Add(y, term)
		xi.Mul(xi, x)
	}
	return y
}

// InterpolateInterpolates the polynomial at x=0 using the given shares (x, y).
func Interpolate(yValues []*big.Int, m int) *big.Int {
	xValues := make([]*big.Int, m)
	for i, _ := range yValues {
		yB := yValues[i].Bytes()
		x := new(big.Int)
		x.SetBytes([]byte{yB[len(yB)-1]})
		fmt.Println("x: ", x)
		xValues[i] = x
		yB = yB[:len(yB)-1]
		y := new(big.Int)
		y.SetBytes(yB)
		yValues[i] = y
	}
	secret := big.NewInt(0)
	mod := secp256k1.S256().Params().N // 使用 secp256k1 曲线的阶作为模数
	for j := 0; j < m; j++ {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for i := 0; i < m; i++ {
			if i != j {
				num.Mul(num, xValues[i])
				num.Mod(num, mod)

				temp := new(big.Int).Sub(xValues[i], xValues[j])
				den.Mul(den, temp)
				den.Mod(den, mod)
			}
		}
		invDen := new(big.Int).ModInverse(den, mod) // 计算逆元
		lagrange := new(big.Int).Mul(num, invDen)
		lagrange.Mod(lagrange, mod) // 确保 Lagrange 系数是非负数

		term := new(big.Int).Mul(yValues[j], lagrange)
		term.Mod(term, mod) // 确保 term 是非负数

		fmt.Printf("重构后的分片 %d: (%s, %s)\n", xValues[j], xValues[j], term.Text(16))
		secret.Add(secret, term)
		secret.Mod(secret, mod) // 确保结果是非负数
	}
	return secret
}
