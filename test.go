package main

import (
  "fmt"
"flag"
"crypto/tls"
	"crypto/x509"
	//"flag"
	"io/ioutil"
	"log"
	"net/http"
  "net/url"
    "strings"
)


func main() {
  rec :=  Rectangle{2,4}
  c:= Circle{2}
  fmt.Println(getArea(rec))
  fmt.Println(getArea(c))
  var certFile = flag.String("cert", "certificate.pem", "A PEM eoncoded certificate file.")
	var keyFile  = flag.String("key", "server.key", "A PEM encoded private key file.")
  flag.Parse()

	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {


  }
  caCert, err := ioutil.ReadFile("certificate.pem")
	if err != nil {
		log.Fatalf("Reading server certificate: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
  tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
    InsecureSkipVerify: true,
	}
  tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
  parm := url.Values{}
      parm.Add("client_id", "6192d0cd-46f9-44f2-8a95-01be0d4068f0")
      parm.Add("redirect_uri", "http://localhost:9999")
      parm.Add("grant_type", "authorization_code")
      parm.Add("code", "QCs1I4qK982GiKxfUXTEMjHE2p47YDYzFy")
	// Do GET something
	//resp, err := client.Post("https://sandbox.hsbc.com/psd2/stet/v1.4/token")
  req, err := http.NewRequest("POST", "https://sandbox.hsbc.com/psd2/stet/v1.4/token", strings.NewReader(parm.Encode()))
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(data))
  //d := string(data)
  //log.Println(string(d.access_token))
}
type Shape interface {
  area() float64
}

type Rectangle struct {
  height float64
  width float64
}

type Circle struct {
  radius float64
}

func (rect Rectangle) area() float64{
  return rect.height*rect.width
}
func (c Circle) area() float64{
  return 3.14*c.radius*c.radius
}

func  getArea(s Shape) float64{
  return s.area()
}
