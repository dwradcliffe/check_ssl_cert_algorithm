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

	if len(os.Args) != 2 {
		fmt.Println("UNKNOWN: Must specify domain!")
		os.Exit(3)
	}

	domain := os.Args[1]

	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		fmt.Println("UNKNOWN: Failed to connect: " + err.Error())
		os.Exit(3)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	for i := 0; i < len(certs); i++ {
		if certs[i].SignatureAlgorithm == x509.SHA1WithRSA {
			fmt.Println("WARNING: SHA-1 found for " + domain + "; " + strconv.Itoa(len(certs)) + " certificates total")
			os.Exit(1)
		}
	}

	fmt.Println("OK: " + domain + " has a full certificate chain signed with SHA-2.")

}
