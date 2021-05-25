package main

import (
	"mosaic/abe"
	"mosaic/abe/log"
)

func main() {
	log.Init("Info")

	seed := "abcdef"
	curve := abe.NewCurve()
	curve.SetSeed(seed).InitRng()
	org := abe.NewRandomOrg(curve)
	authkeys := abe.NewRandomAuth(org)
	user := "marcello.paris@gmail.com"

	policies := []string{
		"A@auth0",
	}

	for _, policy := range policies {
		log.Info("----------------")
		log.Info("policy: %s", policy)

		// ecnrypting
		secret := abe.NewRandomSecret(org)
		policy = abe.RewritePolicy(policy)
		authpubs := abe.AuthPubsOfPolicy(policy)
		for attr, _ := range authpubs.AuthPub {
			authpubs.AuthPub[attr] = authkeys.AuthPub
		}
		ct := abe.Encrypt(secret, policy, authpubs)

		// decrypting
		userattrs_A := abe.NewRandomUserkey(user, "A@auth0", authkeys.AuthPrv)
		userattrs_B := abe.NewRandomUserkey(user, "B@auth0", authkeys.AuthPrv)
		userattrs := userattrs_A.Add(userattrs_B)
		userattrs.SelectUserAttrs(user, policy)

		secret_dec := abe.Decrypt(ct, userattrs)

		if abe.SecretHash(secret) == abe.SecretHash(secret_dec) {
			log.Info("secret correctly reconstructed")
		} else {
			log.Info("secret not correctly reconstructed")
		}
	}
}