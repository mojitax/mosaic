package main

import (
    "bufio"
    "flag"
    "fmt"
    "os"
    "time"
	
    mqtt "github.com/eclipse/paho.mqtt.golang"
    "encoding/json"
	
	"mosaic/abe"
	
	
)

func main() {
    // 1 - Read a client identifier from a command line flag
    var clientName string
    flag.StringVar(&clientName, "client", "", "the client name")
    flag.Parse()
    if len(clientName) == 0 {
            panic("-client is required")
    }
    // 2 - Connect to a MQTT broker 
    brokerEndpoint := "18.221.34.191:1883"
    mqttClient, err := initMQTT(brokerEndpoint, clientName)
    if err != nil {
            panic(fmt.Sprintf("failed to init mqtt client: %v", err))
    }
    fmt.Printf("> connected to %s\n", brokerEndpoint)
    
    messageTopic := "testB"
    
	policy:="A@auth0"
	file, _ := os.Open("new_files/org.json")
	reader := bufio.NewReader(file)
	orgStr, _:=reader.ReadString('\n')
	
	org := new(abe.Org)
	json.Unmarshal([]byte(orgStr), org)
	org.OfJsonObj()
	
	file2, _ := os.Open("new_files/authpub.json")
	reader2 := bufio.NewReader(file2)
	authpubStr, _:=reader2.ReadString('\n')
	
	authpub := new(abe.AuthPub)
	
	json.Unmarshal([]byte(authpubStr), authpub)
	authpub.OfJsonObj()
	if abe.CheckPolicyJson(policy, "") == "sat" {
		// ecnrypting
		secret := abe.NewRandomSecret(org)
		policy = abe.RewritePolicy(policy)
		authpubs := abe.AuthPubsOfPolicy(policy)
		for attr, _ := range authpubs.AuthPub {
			authpubs.AuthPub[attr] = authpub
		}
		
        secret_enc:=abe.Encrypt(secret, policy, authpubs)
		secret_enc.ToJsonObj()
		secret_encJson, _ :=json.Marshal(secret_enc)
		secret_hash := abe.SecretHash(secret)
		fmt.Printf("%s", secret_hash)
        if token := mqttClient.Publish(messageTopic, 1, true, secret_encJson); token.Wait() && token.Error() != nil {
                fmt.Printf("> failed to publish message: %v\n", token.Error())
                
        }
		
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