package api_sec

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

type Log struct {
	Req struct {
		URL        string `json:"url"`
		QSParams   string `json:"qs_params"`
		Headers    string `json:"headers"`
		ReqBodyLen int    `json:"req_body_len"`
	} `json:"req"`
	Rsp struct {
		StatusClass string `json:"status_class"`
		RspBodyLen  int    `json:"rsp_body_len"`
	} `json:"rsp"`
}

// logRequest logs the request and response
func createLog(w http.ResponseWriter, r *http.Request, statusCode int, bodyLen int) {
	reqURL := r.URL.String()
	qParams := r.URL.Query().Encode()
	headers := fmt.Sprintf("%v", r.Header)
	reqBodyLen := int(r.ContentLength)

	currLog := Log{}
	currLog.Req.URL = reqURL
	currLog.Req.QSParams = qParams
	currLog.Req.Headers = headers
	currLog.Req.ReqBodyLen = reqBodyLen

	//Compute status class
	statusClass := strconv.Itoa(statusCode/100) + "xx"
	currLog.Rsp.StatusClass = statusClass
	currLog.Rsp.RspBodyLen = bodyLen

	//Marshal the current log into json format
	logData, err := json.Marshal(currLog)
	if err != nil {
		log.Println("Can not marshal log", err)
		return
	}

	//Create access.log file
	file, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Println("Can not open log file", err)
		return
	}
	defer file.Close()

	//Write the log to the file
	_, err = file.Write(append(logData, '\n', '\n'))
	if err != nil {
		log.Println("Error writing log:", err)
	}
}

func LogMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//Capture the original ResponseWriter to count the response size
		recorder := &ResponseRecorder{ResponseWriter: w, StatusCode: http.StatusOK}
		next(recorder, r)
		createLog(recorder, r, recorder.StatusCode, recorder.BodyLen)
	}
}

// wraps the http.ResponseWriter to allow acess to the response status and body length
type ResponseRecorder struct {
	http.ResponseWriter
	StatusCode int
	BodyLen    int
}

// overrides ResponseWriter WriteHeader, captures the status code for the response
func (rec *ResponseRecorder) WriteHeader(statusCode int) {
	rec.StatusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

// overrides ResponseWriter Write, captures the status code for the response
func (rec *ResponseRecorder) Write(rspBody []byte) (n int, err error) {
	n, err = rec.ResponseWriter.Write(rspBody)
	rec.BodyLen += n
	return n, err
}
