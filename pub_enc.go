package main

import (
        //"bufio"
        "flag"
        "fmt"
        "os"
        "time"

        mqtt "github.com/eclipse/paho.mqtt.golang"
        
	"mosaic/service"
	"github.com/marcellop71/mosaic/abe"
	"path/filepath"
	
)

func main() {
        // 1 - Read a client identifier from a command line flag
        var clientName string
        flag.StringVar(&clientName, "client", "", "the client name")
        flag.Parse()

        if len(clientName) == 0 {
                panic("-client is required")
        }

        // 2 - Connect to a MQTT broker (we'll use our public mqtt.teserakt.io:1338)
        brokerEndpoint := "18.221.34.191:1883"
        mqttClient, err := initMQTT(brokerEndpoint, clientName)
        if err != nil {
                panic(fmt.Sprintf("failed to init mqtt client: %v", err))
        }
        fmt.Printf("> connected to %s\n", brokerEndpoint)

        // 3 - Subscribe to message MQTT topic and print incoming messages to stdout
        messageTopic := "testB"
       /* token := mqttClient.Subscribe(messageTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
                fmt.Printf("< received raw message on %s: %s\n", msg.Topic(), msg.Payload())
        })
        timeout := time.Second
        if !token.WaitTimeout(timeout) {
                panic(fmt.Sprintf("failed to subscribe to MQTT topic: %v\n", token.Error()))
        }
        fmt.Printf("> subscribed to MQTT topic %s\n", messageTopic)*/
        filename, _ := filepath.Abs("./examples/config.yaml")
	
	config := service.ReadConfig(filename).Config
	service.InitAbeService(config, nil)

	policy:="A@auth0"
	org := "org0"
        secret_enc := ""
	if abe.CheckPolicyJson(policy, "") == "sat" {
		// ecnrypting
		secretJson := service.NewRandomSecret(org)
		//secret := abe.NewPointOfJsonStr(secretJson).GetP()
		//secret_hash := sha256.Sum256([]byte(secret))

		policy = abe.RewritePolicy(policy)
		authpubsJson := abe.AuthPubsOfPolicyJson(policy)
		authpubsJson = service.FetchAuthPubs(authpubsJson)
		secret_enc = abe.EncryptJson(secretJson, policy, authpubsJson)
		//fmt.Printf("%s\n", []byte(secret_enc))
		f, _ := os.Create("files/ciphertext")
		
		f.WriteString(secret_enc)
        }
        // 4 - Wait for user input on stdin and publish messages
        // on the peer MQTT topic `/e4go/demo/messages` once user press the enter key.
        

        if token := mqttClient.Publish(messageTopic, 1, true, secret_enc); token.Wait() && token.Error() != nil {
                fmt.Printf("> failed to publish message: %v\n", token.Error())
                
        }


}

func initMQTT(brokerEndpoint, clientID string) (mqtt.Client, error) {
        opts := mqtt.NewClientOptions()
        opts.AddBroker(brokerEndpoint)
        opts.SetClientID(clientID)
        opts.SetCleanSession(true)

        mqttClient := mqtt.NewClient(opts)
        timeout := time.Second
        if token := mqttClient.Connect(); token.WaitTimeout(timeout) && token.Error() != nil {
                return nil, token.Error()
        }

        return mqttClient, nil
}