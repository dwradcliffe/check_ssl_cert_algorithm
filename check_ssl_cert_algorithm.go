// Check a ssl cert for SHA-1 algorthm
//
// Copyright 2014 David Radcliffe <radcliffe.david@gmail.com>

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
)

func main() {

	domain := os.Args[1]

	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	for i := 0; i < len(certs); i++ {
		if certs[i].SignatureAlgorithm == x509.SHA1WithRSA {
			fmt.Println("WARNING: SHA-1 found for " + domain + "; " + strconv.Itoa(len(certs)) + " certificates total")
			os.Exit(2)
		}
	}

	fmt.Println("OK: " + domain + " has a full certificate chain signed with SHA-2.")

}
