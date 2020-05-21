/*
A "JWE" decrypter plugin in Go,
which reads the Authorization Bearer request header and replaces with the decrypted data (a JWS)
*/
package main

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/Kong/go-pdk"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
	"math/big"
	"regexp"
	"time"
)

var Priority = 5000

var defaultKeysetJWK = `{"keys":[{"p":"4cAQuJBDe2tB9aNC4wFjdj29Ujqu4wOFpIM_FlYaCQAK-E9IdyHZVVzENOC_AP83ZpEoJI6q5kDB7IqvOwSf9myEX5Y2TmHxMGvPiSG4ymuuoAuW3PNRDmm1YH5COIhUNq8JGz-9-svuQiLttMdCY_G3m_m0F-tvntiZED_v4Rs","kty":"RSA","q":"vz6A-_lAvojmOdwEvmSJJYIs6uPP77bDqtQX4EVx5hFObhd-psiprPGsa6XK7Mysyd-ch_rmGvqnnobDfELyMdhbydErA_g0eCxRDk6NiKfE_gJ2VrRogcdRFLI53Z0deU77KNKC5S1kcXHPC_DQy82vlRKqTHYLubm_NVSiCeM","d":"EYGSUc8yyzhiqKRf6mo5FFU7mn8LiDj-pLIbjrB4FkMrSsJ5wTj_8qSeQurFHMXCOGRt72fkp7vQ66yvLR4vOYDxrnMFxs3AKkVsTpLUxZezXVJyhZcBi-TD2A9bjqT5np_geudYJWcIviT-tFbkxqkVE_pKeXYcCVI1fmNsu2F93y92AdzT6RYmtqVc7WqOBrekaAtpgApoSvF-aQg4j3-6hyS5b_WdqkrQ_TCJM9rTESqQ-mAPZXBCzslJHnz1eTDsUlgZuOmejhtFbXhItHVjIDnNCGIzC-rFM-yywjwrKLRqA808ty5pbDcBf5WCGyo4a9AzXI1i_WJx_1NaHQ","e":"AQAB","use":"enc","kid":"d057aeda93bd3391a0088649378b4dc1c5bc762d","qi":"cWCvQ1cDyN-v7kKQ2VfoS115PPwgwGDrztOOwmhMHP-j49212pMlGnNowxNhr00gTml6AjuUCXkToa4c8d1T2XJYId0dvG7cyXORmcCLPxHHGit3TS7ADfPcLMWwFbPsgZdf2iDU49WbTmqOopjLP7aiuJ-5G1eUPUtDA8QQMDM","dp":"1DoGvivJdP6JfM6l89j7U06JbAOFJB_MhLNqHKqHQUzMA1Itkum8cnaKcheTGPHVeFQgQ_Xnjhz08lYSlE4tv7GW5HHHzfpfjyDbc1TDb3C6MvWSN1d7LSyNehBYWuM3IE1_JyHOjTcoXv6NL7Vfoau87CJcf1wzjEad5tvkvF8","alg":"RSA-OAEP-256","dq":"vKre-LYnR1ErP31tOJ9aJaTMx1XDt4socYkXnOsluIDuTPHkwolHyxQIs5I2JXKuK-HsPMIq7AbIAj6U8CvjX4VA2FMACsR8jum5dVHNkzlfv--R62vDhfSqaq6BI75ya1CduuIivBER_FD4n6ENe2IJjBmD5Da4zpsOpYA-810","n":"qKVqu_vO3tER_QdInm3v6kLnkVDLLUoNO_k8bUej1TlLXwIWyu6Lvv7xWCG3zrykJlUOoc30K4S_S0ifBNSMueabPY1i2UKuFE4RPBA7UlDKfYczSq2-tRboNgHd-23abgMz2LUKwLZc10_FWMFP32gdFzG6EsMOsSxln-0m08yKtHzAl1IYFUYrY0ken74mxE4m-wpqPrRX7yIH0xNGeQgxyg5yzGjN2Jl3eI9cyIsTzan_2VgsmeOzconHo-tDyFVwAjUvBINWn_KqNNhpm2BVwJFVALEmdE01IYEKtD-6oww7pnOexq1gQMzFyKHx3vMfqhBQxBoN1Dbob7SN8Q"}]}`

// publicKeysetJWK = {"keys":[{"kty":"RSA","e":"AQAB","kid":"d057aeda93bd3391a0088649378b4dc1c5bc762d","n":"qKVqu_vO3tER_QdInm3v6kLnkVDLLUoNO_k8bUej1TlLXwIWyu6Lvv7xWCG3zrykJlUOoc30K4S_S0ifBNSMueabPY1i2UKuFE4RPBA7UlDKfYczSq2-tRboNgHd-23abgMz2LUKwLZc10_FWMFP32gdFzG6EsMOsSxln-0m08yKtHzAl1IYFUYrY0ken74mxE4m-wpqPrRX7yIH0xNGeQgxyg5yzGjN2Jl3eI9cyIsTzan_2VgsmeOzconHo-tDyFVwAjUvBINWn_KqNNhpm2BVwJFVALEmdE01IYEKtD-6oww7pnOexq1gQMzFyKHx3vMfqhBQxBoN1Dbob7SN8Q"}]}

var privateKeyset []*rsa.PrivateKey

var authBearerRe *regexp.Regexp = regexp.MustCompile(`^[Bb]earer\s([^\s]+)$`)

var jsonErrorTemplate = `{"code": "%s", "message": "%s"}`
var headerErrorCodes = map[int]string{
	400: "invalid_request",
	401: "invalid_token",
	403: "insufficient_scope",
}
var bodyErrorCodes = map[int]string{
	400: "INVALID_ARGUMENT",
	401: "UNAUTHENTICATED",
	403: "PERMISSION_DENIED",
	404: "NOT_FOUND",
	500: "INTERNAL",
}

type privateKeysJWK struct {
	Keys []rawJSONWebKey `json:"keys"`
}

type rawJSONWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	Dp string `json:"dp,omitempty"`
	Dq string `json:"dq,omitempty"`
	Qi string `json:"qi,omitempty"`
}

type Config struct {
	JwkSet string `json:jwkset`
}

func New() interface{} {
	return &Config{}
}

func loadPrivateKey(kong *pdk.PDK, conf Config) error {
	var privateKeysetJWK = defaultKeysetJWK
	if conf.JwkSet != "" {
		privateKeysetJWK = conf.JwkSet
	}
	var parsed privateKeysJWK
	err := json.Unmarshal([]byte(privateKeysetJWK), &parsed)
	if err != nil {
		return errors.New("Error loading private key JWK set: " + err.Error())
	}

	for i, privateKey := range parsed.Keys {
		privateKeyset = append(privateKeyset, &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: fromBase64BigInt(privateKey.N, kong),
				E: fromBase64Int(privateKey.E, kong),
			},
			D:           fromBase64BigInt(privateKey.D, kong),
			Primes:      []*big.Int{fromBase64BigInt(privateKey.P, kong), fromBase64BigInt(privateKey.Q, kong)},
			Precomputed: rsa.PrecomputedValues{Dp: fromBase64BigInt(privateKey.Dp, kong), Dq: fromBase64BigInt(privateKey.Dq, kong), Qinv: fromBase64BigInt(privateKey.Qi, kong)},
		})
		err = privateKeyset[i].Validate()
		if err != nil {
			return errors.New("Invalid private key: " + err.Error())
		}
	}
	kong.Log.Notice("Loaded private keyset to decrypt JWE tokens")
	return nil
}

//Send a JSON error response following https://tools.ietf.org/html/rfc6750#section-2.3
func SendErrorResponse(kong *pdk.PDK, statusCode int, message string) {
	headers := map[string][]string{}
	code, ok := headerErrorCodes[statusCode]
	if ok {
		errHeader := fmt.Sprintf(`Bearer realm="Kong",error="%s",error_description="%s"`, code, message)
		headers["WWW-Authenticate"] = []string{errHeader}
	}
	kong.Response.Exit(statusCode, fmt.Sprintf(jsonErrorTemplate, bodyErrorCodes[statusCode], message), headers)
}

func (conf Config) Access(kong *pdk.PDK) {
	if privateKeyset == nil {
		err := loadPrivateKey(kong, conf)
		if err != nil {
			kong.Log.Err(err.Error())
			SendErrorResponse(kong, 500, "jwe plugin can not load JWK set to start")
			return
		}
	}

	authorization, err := kong.Request.GetHeader("Authorization")
	if err != nil {
		kong.Log.Err("Error getting Authorization Header: " + err.Error())
		return
	}
	bearerToken := authBearerRe.FindStringSubmatch(authorization)
	if len(bearerToken) == 0 {
		kong.Log.Err("Invalid Authorization Header (not a Bearer token)")
		SendErrorResponse(kong, 500, "Token can not be get")
		return
	}

	t1 := makeTimestamp()

	obj, err := jose.ParseEncrypted(bearerToken[1])
	if err != nil {
		s := fmt.Sprintf(fmt.Sprintf("Not a JWE, nothing to do here: %s", err.Error()))
		kong.Log.Notice(s)
		return
	}
	jws, err := obj.Decrypt(privateKeyset[0])
	if err != nil {
		kong.Log.Err("unable to decrypt message", err)
		SendErrorResponse(kong, 401, "Invalid token")
		return
	}
	//replacing authorization with decrypted jws (it should be so)
	kong.ServiceRequest.SetHeader("Authorization", fmt.Sprintf("Bearer %s", string(jws)))

	t2 := makeTimestamp()
	kong.Log.Notice(fmt.Sprintf("Time for decrypting %d", t2-t1))

}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func fromBase64BigInt(encoded string, kong *pdk.PDK) *big.Int {
	re := regexp.MustCompile(`\s+`)
	val, err := base64.RawURLEncoding.DecodeString(re.ReplaceAllString(encoded, ""))
	if err != nil {
		kong.Log.Err("Invalid test data: " + err.Error())
	}
	return new(big.Int).SetBytes(val)
}

func fromBase64Int(encoded string, kong *pdk.PDK) int {
	re := regexp.MustCompile(`\s+`)
	val, err := base64.RawURLEncoding.DecodeString(re.ReplaceAllString(encoded, ""))
	if err != nil {
		kong.Log.Err("Invalid test data: " + err.Error())
	}

	return int(new(big.Int).SetBytes(val).Int64())
}
