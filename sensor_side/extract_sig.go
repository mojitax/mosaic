package main

import (
	"os"
	"log"
	"flag"


	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"mosaic/sensor_side/chat"
)

func main() {
    var id string
    flag.StringVar(&id, "id", "", "id")
	flag.Parse()
    if len(id) == 0 {
        panic("-id is required")
    }
	
	
	var conn *grpc.ClientConn
	conn, err := grpc.Dial("13.58.65.143:9000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	c := chat.NewChatServiceClient(conn)

	response, err := c.SayHello(context.Background(), &chat.Message{Body: string(id)})
	if err != nil {
		log.Fatalf("Error when calling SayHello: %s", err)
	}
	log.Printf("Response from server: %s", response.Body)
	file,_:=os.Create("new_files/user_sig_keys/"+id+".json")//plik tworzony jest z nazwą użytkownika
	file.WriteString(response.Body)//zapis
}



