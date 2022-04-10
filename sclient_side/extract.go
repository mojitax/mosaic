package main

import (
	"bufio"
	//"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	//"io/ioutil"
	"log"
	"math/rand"
	//"net/http"
	"os"
	"os/exec"
	"time"
	"mosaic/sclient_side/chat"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"github.com/xlzd/gotp"
	"gopkg.in/yaml.v2"
	"flag"
	"fmt"
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
	Indexes []int  `json:"indexes"`
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

//Generate_Key to OTP
func Generate_Key() ([32]byte, []int) {
	NumebrOfParams := 4
	var response string
	var paramnumbers []int
	rand.Seed(time.Now().UnixNano())
	for r := 0; r < NumebrOfParams; r++ {
		newParamNumber := (rand.Intn(len(arrayOfCommands)) + 1)
		if !FindUint(paramnumbers, newParamNumber) {
			paramnumbers = append(paramnumbers, newParamNumber)
		} else {
			r--
		}
	}
	for i := 0; i < (len(paramnumbers)); i++ {
		result := exec.Command("/bin/bash", "-c", arrayOfCommands[paramnumbers[i]-1])
		out, err := result.CombinedOutput()
		if err != nil {
			h := hmac.New(sha256.New, []byte(cfg.HashKey))
			h.Write([]byte(err.Error()))
			sha := hex.EncodeToString(h.Sum(nil))
			response = response + sha
		} else {
			h := hmac.New(sha256.New, []byte(cfg.HashKey))
			h.Write([]byte(out))
			sha := hex.EncodeToString(h.Sum(nil))
			response = response + sha
		}
	}
	key := sha256.Sum256([]byte(response))
	return key, paramnumbers
}

//must - Error handling
func must(err error) {
	if err == nil {
		return
	}
	log.Panicln(err)
}

//readFile - read config file
func readFile(cfg *Config) {
	log.Printf("Reading config file")
	f, err := os.Open("sclient_side/config.yaml")
	if err != nil {
		must(err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(cfg)
	if err != nil {
		must(err)
	}
}

//readCommands - read commands
func readCommands() {
	log.Printf("Reading commands")
	f, err := os.Open("sclient_side/commands.yaml")
	if err != nil {
		must(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		arrayOfCommands = append(arrayOfCommands, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		must(err)
	}
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
	

	// odczyt konfiguracji
	readFile(&cfg)
	// odczyt polecen
	readCommands()
	key, paramnumbers := Generate_Key()
	log.Printf("key: %v", base32.StdEncoding.EncodeToString(key[:]))
	otp := gotp.NewDefaultTOTP(base32.StdEncoding.EncodeToString(key[:]))
	value := otp.At(0)
	log.Printf("ID: %v, paramnumbers:%v, OTP: %s", cfg.ID, paramnumbers, value)
	attrs, _:=readLines(attrsPath)
	message := Auth{cfg.ID, paramnumbers, value, attrs}
	jsonMessage, _ := json.Marshal(message)
	fmt.Printf("%s\n", string(jsonMessage))
	var conn *grpc.ClientConn
	conn, err := grpc.Dial("10.0.123.199:9000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	c := chat.NewChatServiceClient(conn)

	response, err := c.SayHello(context.Background(), &chat.Message{Body: string(jsonMessage)})
	if err != nil {
		log.Fatalf("Error when calling SayHello: %s", err)
	}
	log.Printf("Response from server: %s", response.Body)
	file,_:=os.Create("new_files/user_keys/"+cfg.ID+".json")//plik tworzony jest z nazwą użytkownika
	file.WriteString(response.Body)//zapis
}
