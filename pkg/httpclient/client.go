package httpclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/kosha/payments-ca-fif/pkg/logger"
	"github.com/kosha/payments-ca-fif/pkg/models"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func makeHttpBasicAuthReq(username, password string, method, url string, body interface{}, log logger.Logger) ([]byte, int) {

	var req *http.Request
	fmt.Println(method)
	fmt.Println(url)
	if body != nil {
		s := body.(string)
		req, _ = http.NewRequest(method, url, bytes.NewBuffer([]byte(s)))
	} else {
		req, _ = http.NewRequest(method, url, nil)
	}

	req.Header.Set("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//req.Header.Set("Accept-Encoding", "identity")

	client := &http.Client{}

	resp, err := client.Do(req)

	if err != nil {
		log.Error(err)
		return nil, 500
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
	}
	return bodyBytes, resp.StatusCode
}

func setOauth2Header(newReq *http.Request, tokenMap map[string]string) {
	newReq.Header.Set("Authorization", "Bearer "+tokenMap["access_token"])
	newReq.Header.Set("Content-Type", "application/json")
	newReq.Header.Set("Accept", "application/vnd.fif.api.v1+json")

	newReq.Header.Set("Accept-Encoding", "identity")

	return
}

func Oauth2ApiRequest(headers map[string]string, method, url string, data interface{}, tokenMap map[string]string, log logger.Logger) ([]byte, int) {
	var client = &http.Client{
		Timeout: time.Second * 10,
	}
	var body io.Reader
	if data == nil {
		body = nil
	} else {
		var requestBody []byte
		requestBody, err := json.Marshal(data)
		if err != nil {
			log.Error(err)
			return nil, 500
		}
		body = bytes.NewBuffer(requestBody)
	}

	request, err := http.NewRequest(method, url, body)
	if err != nil {
		log.Error(err)
		return nil, 500
	}
	for k, v := range headers {
		request.Header.Add(k, v)
	}
	setOauth2Header(request, tokenMap)
	response, err := client.Do(request)

	if err != nil {
		log.Error(err)
		return nil, 500
	}
	defer response.Body.Close()
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Error(err)
		return nil, 500
	}
	return respBody, response.StatusCode
}

func MakeHttpCall(headers map[string]string, consumerId, consumerSecret, method, serverUrl, url string, body interface{}, token string, log logger.Logger) (interface{}, int, error) {

	var response interface{}
	var payloadRes []byte

	var statusCode int
	tokenMap := make(map[string]string)

	if token != "" {
		tokenMap["access_token"] = token
		payloadRes, statusCode = Oauth2ApiRequest(headers, method, url, body, tokenMap, log)
		if string(payloadRes) == "" {
			return nil, statusCode, fmt.Errorf("nil")
		}
		// Convert response body to target struct
		err := json.Unmarshal(payloadRes, &response)
		if err != nil {
			log.Error("Unable to parse response as json")
			log.Error(err)
			return nil, http.StatusInternalServerError, err
		}
		if statusCode == 200 && response != nil {
			return response, statusCode, nil
		}
	}
	return nil, http.StatusInternalServerError, fmt.Errorf("token invalid")
}

func GenerateToken(consumerId, consumerSecret, serverUrl string, log logger.Logger) (string, string, error) {
	// token is not generated, or is invalid so get new token
	grantTypeBody := "grant_type=client_credentials"
	token, expiresIn, _ := getToken(consumerId, consumerSecret, serverUrl, log, grantTypeBody)
	if token == "" {
		return "", "", fmt.Errorf("error generating token")
	}
	return token, expiresIn, nil
}

func getToken(consumerId, consumerSecret, serverUrl string, log logger.Logger, body interface{}) (string, string, int) {

	var tokenResponse models.AccessToken

	url := serverUrl + "/accesstoken"
	res, _ := makeHttpBasicAuthReq(consumerId, consumerSecret, "POST", url, body, log)
	if string(res) == "" {
		return "", "", 500
	}
	// Convert response body to target struct
	err := json.Unmarshal(res, &tokenResponse)
	if err != nil {
		log.Error("Unable to parse auth token response as json")
		log.Error(err)
		return "", "", 500
	}
	return tokenResponse.AccessToken, tokenResponse.ExpiresIn, 200
}
