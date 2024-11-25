package api_sec

import (
	"encoding/json"
	// "fmt"
	"strings"
	"log"
	"net/http"
	"os"
	"strconv"
)

type LogData struct {
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

//logRequest logs the request and response
func createLog(r *http.Request, statusCode int, bodyLen int) {
	reqURL := r.URL.String()
	qParams := r.URL.Query().Encode()

    var headersBuilder strings.Builder
    
    //iterate over all headers and append them to the string builder
    for key, values := range r.Header {
        headersBuilder.WriteString(key + ": " + strings.Join(values, ", ") + "\n")
    }

	reqBodyLen := int(r.ContentLength)

	currLog := LogData{}
	currLog.Req.URL = reqURL
	currLog.Req.QSParams = qParams
	currLog.Req.Headers = headersBuilder.String()
	currLog.Req.ReqBodyLen = reqBodyLen

	//compute status class
	statusClass := strconv.Itoa(statusCode/100) + "xx"
	currLog.Rsp.StatusClass = statusClass
	currLog.Rsp.RspBodyLen = bodyLen

	//marshal the current log into json format
	logData, err := json.Marshal(currLog)
	if err != nil {
		log.Println("Can not marshal log", err)
		return
	}

	//create access.log file
	file, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Println("Can not open log file", err)
		return
	}
	defer file.Close()

	//write the log to the file
	_, err = file.Write(append(logData, '\n', '\n'))
	if err != nil {
		log.Println("Error writing log:", err)
	}
}

func LogMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//capture the original ResponseWriter to count the response size and status code
		recorder := &ResponseRecorder{ResponseWriter: w, StatusCode: http.StatusOK}
		next(recorder, r)
		createLog(r, recorder.StatusCode, recorder.BodyLen)
	}
}

//wraps the http.ResponseWriter to allow acess to the response status and body length
type ResponseRecorder struct {
	http.ResponseWriter
	StatusCode int
	BodyLen    int
}

//overrides ResponseWriter WriteHeader, captures the status code for the response
func (rec *ResponseRecorder) WriteHeader(statusCode int) {
	rec.StatusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

//overrides ResponseWriter Write, captures the status code for the response
func (rec *ResponseRecorder) Write(rspBody []byte) (n int, err error) {
	n, err = rec.ResponseWriter.Write(rspBody)
	rec.BodyLen += n
	return n, err
}
