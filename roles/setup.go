package main

import(
	//"github.com/marcellop71/mosaic/abe"
	"mosaic/service"
	//"fmt"
	//"os"
	//"bufio"
	"path/filepath"
)

func main(){
	filename, _ := filepath.Abs("./examples/config.yaml")
	
	config := service.ReadConfig(filename).Config
	service.InitAbeService(config, nil)

	lib := "miracl"
	org := "org0"
	service.SetupOrg(org, lib, config.Arithmetic.Curve, config.Arithmetic.Seed)
	
	auths := []string{"auth0", "auth1"}
	for _, auth := range auths {
		service.SetupAuth(auth, org)
	}
	
}