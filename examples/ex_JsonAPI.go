package main

import (
	"crypto/sha256"
	"path/filepath"
	"fmt"
	"github.com/marcellop71/mosaic/abe"
	"github.com/marcellop71/mosaic/abe/log"
	"github.com/marcellop71/mosaic/service"
)

func main() {
	log.Init("Info")

	filename, err := filepath.Abs("./examples/config.yaml")
	if err != nil {
		log.Panic("%s", err)
	}
	config := service.ReadConfig(filename).Config
	service.InitAbeService(config, nil)

	lib := "miracl"
	org := "org0"
	service.SetupOrg(org, lib, config.Arithmetic.Curve, config.Arithmetic.Seed)
	log.Info("set up organization %s on curve %s", org, config.Arithmetic.Curve)

	auths := []string{"auth0", "auth1"}
	for _, auth := range auths {
		service.SetupAuth(auth, org)
	}
	log.Info("set up authorities %s on organization %s", auths, org)

	user := "marcello.paris@gmail.com"
	attrs := []string{"A@auth0", "B@auth0"}
	for _, attr := range attrs {
		service.SetupUserkey(user, attr)
	}
	log.Info("user %s asking for keys for attributes %s", user, attrs)

	policies := []string{
		"A@auth0",
		/*"A@auth0 /\\ B@auth0",
		"A@auth0 /\\ A@auth0",
		"A@auth0 /\\ (B@auth0 /\\ (C@auth0 \\/ D@auth0))",
		"A@auth0 /\\ ((D@auth0 \\/ (B@auth0 /\\ C@auth0)) \\/ A@auth0)",
		"(A@auth0 \\/ C@auth0) /\\ (D@auth0 \\/ (B@auth0 /\\ C@auth0))",
		"(/\\ A@auth0 (\\/ A@auth0 D@auth0 (/\\ B@auth0 C@auth0)))",
		"(A@auth0 /\\ B@auth0) \\/ (A@auth0 /\\ C@auth0) \\/ (B@auth0 /\\ C@auth0)",
		"A@auth0 /\\ B@auth0 /\\ C@auth0",*/
	}

	for _, policy := range policies {
		log.Info("----------------")
		log.Info("policy: %s", policy)
		if abe.CheckPolicyJson(policy, "") == "sat" {
			// ecnrypting
			secretJson := service.NewRandomSecret(org)
			secret := abe.NewPointOfJsonStr(secretJson).GetP()
			secret_hash := sha256.Sum256([]byte(secret))
			log.Info("secret hash: %s", abe.Encode(string(secret_hash[:])))

			policy = abe.RewritePolicy(policy)
			authpubsJson := abe.AuthPubsOfPolicyJson(policy)
			authpubsJson = service.FetchAuthPubs(authpubsJson)
			secret_enc := abe.EncryptJson(secretJson, policy, authpubsJson)
			
			// decrypting
			policy = abe.PolicyOfCiphertextJson(secret_enc)
			userattrsJson := service.FetchUserAttrs(user)
			//fmt.Printf("%s", secret_enc)
			if abe.CheckPolicyJson(policy, userattrsJson) == "sat" {
				userattrsJson = abe.SelectUserAttrsJson(user, policy, userattrsJson)
				userattrsJson = service.FetchUserkeys(userattrsJson)
				secret_dec := abe.DecryptJson(secret_enc, userattrsJson)
				secret_dec_hash := sha256.Sum256([]byte(secret_dec))
				fmt.Printf("%s", secret_dec_hash)
				if abe.Encode(string(secret_dec_hash[:])) == abe.Encode(string(secret_hash[:])) {
					log.Info("secret correctly reconstructed")
				} else {
					log.Info("secret not correctly reconstructed")
				}
			} else {
				log.Info("user cannot satisfy the policy")
			}
		} else {
			log.Info("policy unsatisfiable")
		}
	}
}
