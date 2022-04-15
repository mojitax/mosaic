package main

import (
	"bufio"
	//"bytes"
	//"net/http"
	//"io/ioutil"

	"encoding/json"
	
	"log"

	
	"os"


	"mosaic/sclient_side/chat"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"github.com/xlzd/gotp"

	"flag"
	"fmt"
	//"time"
	//"strings"
)

//Response Struct
type Response struct {
	Message string
	Ok      bool
}

//Message - struct to return Key + params for specific deviceID
type Auth struct {
	ID      string `json:"ID"`
	TOTP    string `json:"TOTP"`
	Attributes []string `json:"Attributes"`
}

// Config exported
type Config struct {
	TemporaryID               string `yaml:"Temporary_ID"`
	TemporaryKey              string `yaml:"Temporary_Key"`
	ID                        string `yaml:"ID"`
	CountOfParams             uint   `yaml:"Count_Of_Params"`
	HashKey                   string `yaml:"Hash_Key"`
	AGIP                      string `yaml:"AG_IP"`
	AGPort                    string `yaml:"AG_Port"`
	ListenIP                  string `yaml:"Listen_IP"`
	ListenPort                uint   `yaml:"Listen_Port"`
	ListenPortForOtherDevices uint   `yaml:"Listen_Port_For_Others"`
}

var (
	cfg Config
)

var arrayOfCommands []string

//ParametersType - struct for Parameter
type ParametersType struct {
	Number uint32 `json:"Number"`
	Value  string `json:"Value"`
}

// Handler holds the methods to be exposed by the RPC
// server as well as properties that modify the methods'
// behavior.
type Handler struct {
}

//FindUint - Check if uint is in array
func FindUint(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
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
    var attrsPath string
    flag.StringVar(&attrsPath, "attrs", "", "path to attributes")
	flag.Parse()
    if len(attrsPath) == 0 {
        panic("-attrs is required")
    }
	seed, _:=readLines("/mosaic/new_files/seedkey")
	if (len(seed)!=2){
		log.Fatalf("Wrong seed file")
	}
	id:=seed[0]
	key:=seed[1]
	otp := gotp.NewDefaultTOTP(key)
	value := otp.Now()
	log.Printf("ID: %v, OTP: %s", id, value)




	attrs, _:=readLines(attrsPath)
	message := Auth{id, value, attrs}
	jsonMessage, _ := json.Marshal(message)
	fmt.Printf("%s\n", string(jsonMessage))
	var conn *grpc.ClientConn
	conn, err := grpc.Dial("10.0.123.199:9000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	c := chat.NewChatServiceClient(conn)

	response2, err := c.SayHello(context.Background(), &chat.Message{Body: string(jsonMessage)})
	if err != nil {
		log.Fatalf("Error when calling SayHello: %s", err)
	}
	//log.Printf("Response from server: %s", response2.Body)
	file,_:=os.Create("new_files/user_keys/"+id+".json")//plik tworzony jest z nazwą użytkownika
	file.WriteString(response2.Body)//zapis
}
