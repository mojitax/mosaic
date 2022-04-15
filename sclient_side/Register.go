package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"flag"
	"os"
	"bufio"
)

type User struct {
	ID         string      `json:"ID"`
	Attributes []attribute `json:"attributes"`
}
type attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AuthUser struct {
	ID   string `json:"ID"`
	TOTP string `json:"TOTP"`
}
func readLines(path string) ([]string, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    return lines, scanner.Err()
}
func main() {
	// REJESTRACJA UŻYTKOWNIKA - ODKOMENTOWAĆ LINIJKI
	var attrsPath string
	var attrsNPath string
	var id string
	flag.StringVar(&id, "id", "", "id")
	flag.Parse()
    if len(id) == 0 {
        panic("-id is required")
    }
	flag.StringVar(&attrsPath, "attrs", "", "path to attributes")
	flag.Parse()
    if len(attrsPath) == 0 {
        attrsPath="/mosaic/sclient_side/attrs"
    }
	flag.StringVar(&attrsNPath, "nattrs", "", "path to attribute names")
	flag.Parse()
    if len(attrsNPath) == 0 {
        attrsNPath="/mosaic/sclient_side/nattrs"
    }
	var attrib []attribute
	attrs, _:=readLines(attrsPath)
	nattrs, _:=readLines(attrsNPath)
	if len(attrs) != len(nattrs) {
        panic("attrs and nattrs don't match")
    }
	for nr, _:= range attrs{
		attrib = append(attrib, attribute{nattrs[nr], attrs[nr]})
	}
	UserObject := User{ID: id, Attributes: attrib}
	jsonValue, _ := json.Marshal(UserObject)
	log.Println(string(jsonValue))

	response, err := http.Post("http://hlf.semaciti.net:8090/RegisterUser", "application/json", bytes.NewBuffer(jsonValue))
	// DO TĄD

	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		data, _ := ioutil.ReadAll(response.Body)
		fmt.Println(string(data))
		log.Println(response.StatusCode)
		log.Printf("%v", response.Status)
		secretlocation:=strings.Index(string(data), "secret=")
		secret:=string(data)[secretlocation+7:secretlocation+27]
		fmt.Println(secret)
		file,_:=os.Create("/mosaic/new_files/seedkey")//plik tworzony jest z nazwą użytkownika
		file.WriteString(id+"\n"+secret)//zapis

	}
	
	fmt.Println("Terminating the application...")
}
