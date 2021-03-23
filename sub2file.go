package main

import (
        //"bufio"
        "flag"
        "fmt"
        "os"
        "time"
	//"github.com/marcellop71/mosaic/abe"
	//"mosaic/service"
	//"path/filepath"
	//"crypto/sha256"
        mqtt "github.com/eclipse/paho.mqtt.golang"
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




        // 3 - Subscribe to message MQTT topic and print incoming messages to stdout and write to file
        messageTopic := "testB"
        token := mqttClient.Subscribe(messageTopic, 1, func(_ mqtt.Client, msg mqtt.Message) {
                fmt.Printf("< received raw message on %s: %s\n", msg.Topic(), msg.Payload())
                f, _ := os.Create("files/ciphertext2")
		f.WriteString(string(msg.Payload()))


        })
        //timeout := time.Second
        if !token.Wait() {
                panic(fmt.Sprintf("failed to subscribe to MQTT topic: %v\n", token.Error()))
        }
        fmt.Printf("> subscribed to MQTT topic %s\n", messageTopic)

       for {}
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