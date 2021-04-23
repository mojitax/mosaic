package main

import (
	"os"
	"log"
	"flag"
	"fmt"
	"strings"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io/ioutil"
	"mosaic/sclient_side/chat"
)

func main() {
    var attrsPath string
    flag.StringVar(&attrsPath, "attrs", "", "path to attributes")
	flag.Parse()
    if len(attrsPath) == 0 {
        panic("-attrs is required")
    }
	
    attrs, _:=ioutil.ReadFile(attrsPath)
    fmt.Printf("%s\n", string(attrs))
	
	var conn *grpc.ClientConn
	conn, err := grpc.Dial("13.58.65.143:9000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	c := chat.NewChatServiceClient(conn)

	response, err := c.SayHello(context.Background(), &chat.Message{Body: string(attrs)})
	if err != nil {
		log.Fatalf("Error when calling SayHello: %s", err)
	}
	log.Printf("Response from server: %s", response.Body)
	first := strings.Split(string(attrs), "\n") 
	file,_:=os.Create("new_files/user_keys/"+first[0]+".json")//plik tworzony jest z nazwą użytkownika
	file.WriteString(response.Body)//zapis
}
