package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/julienschmidt/httprouter"
)

type Link struct {
	Rel    string `json:"rel"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

type Client struct {
	Name    string `json:"name"`
	Serial  string `json:"serial"`
	Created string `json:"created"`
	Revoked string `json:"revoked"`
	Reason  string `json:"reason"`
	Links   []Link `json:"links"`
}

type NewCertificate struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type RevokeReason struct {
	Reason string `json:"reason"`
}

type OrganizationCertificate struct {
	Name       string `json:"name"`
	CommonName string `json:"commonName"`
	Country    string `json:"country"`
	Province   string `json:"province"`
	City       string `json:"city"`
	Email      string `json:"email"`
	Department string `json:"department"`
}

type CaCert struct {
	Type         string                  `json:"type"`
	Organization OrganizationCertificate `json:"organization"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	Links []Link `json:"links"`
}

func (c Client) withLinks() Client {
	if c.Revoked != "" {
		return c
	}
	c.Links = []Link{
		{Rel: "renew", Method: "PATCH", Path: fmt.Sprintf("/clients/%s", c.Name)},
		{Rel: "revoke", Method: "DELETE", Path: fmt.Sprintf("/clients/%s", c.Name)},
	}
	return c
}

func main() {
	r := httprouter.New()
	r.POST("/ca-certs", createCACertificate)
	r.POST("/servers", createServerCertificate)
	r.POST("/clients", createClientCertificate)
	r.GET("/certificates", getCertificates)
	r.PATCH("/certificates/:name", renewCertificate)
	r.DELETE("/certificates/:name", deleteCertificate)
	log.Fatal(http.ListenAndServe(":8080", r))
}

func hasCACertificate() bool {
	_, err := os.Stat("/usr/share/easy-rsa/pki/ca.crt")
	return err == nil
}

func createCACertificate(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if hasCACertificate() {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "CA certificate already exists"})
		return
	}

	var cert CaCert
	json.NewDecoder(r.Body).Decode(&cert)

	if cert.Type != "common" && cert.Type != "organization" {
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid CA type"})
		return
	}

	cmd := exec.Command("/usr/share/easy-rsa/easyrsa", "build-ca", "nopass")

	if cert.Type == "organization" {
		cmd.Env = cmd.Environ()
		cmd.Env = append(cmd.Env, "EASYRSA_DN=org")
		cmd.Env = append(cmd.Env, fmt.Sprintf("EASYRSA_REQ_ORG=%s", cert.Organization.Name))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EASYRSA_REQ_CN=%s", cert.Organization.CommonName))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EASYRSA_REQ_COUNTRY=%s", cert.Organization.Country))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EASYRSA_REQ_PROVINCE=%s", cert.Organization.Province))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EASYRSA_REQ_CITY=%s", cert.Organization.City))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EASYRSA_REQ_EMAIL=%s", cert.Organization.Email))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EASYRSA_REQ_OU=%s", cert.Organization.Department))
	}

	cmd.Run()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cert)
}

func createServerCertificate(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var cert NewCertificate
	json.NewDecoder(r.Body).Decode(&cert)
	exec.Command("/usr/share/easy-rsa/easyrsa", "build-server-full", cert.Name, cert.Password).Run()
	getCertificates(w, r, p)
}

func createClientCertificate(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var cert NewCertificate
	json.NewDecoder(r.Body).Decode(&cert)
	exec.Command("/usr/share/easy-rsa/easyrsa", "build-client-full", cert.Name, cert.Password).Run()
	getCertificates(w, r, p)
}

func getCertificates(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	file, err := os.Open("/usr/share/easy-rsa/pki/index.txt")
	if err != nil {
		w.WriteHeader(http.StatusTooEarly)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "No CA certificate found",
			Links: []Link{
				{Rel: "create", Method: "POST", Path: "/ca-certs"},
			},
		})
		return
	}
	defer file.Close()
	var clients []Client
	scan := bufio.NewScanner(file)
	scan.Split(bufio.ScanLines)
	for scan.Scan() {
		var client Client
		txt := scan.Text()
		_, err := fmt.Sscanf(txt, "V\t%s\t%s\tunknown /CN=%s", &client.Created, &client.Serial, &client.Name)
		if err != nil {
			_, err := fmt.Sscanf(txt, "R\t%s\t%s\t%s\tunknown /CN=%s", &client.Created, &client.Revoked, &client.Serial, &client.Name)
			if err != nil {
				break
			}
			client.Revoked, client.Reason, _ = strings.Cut(client.Revoked, ",")
		}
		clients = append(clients, client.withLinks())
	}
	json.NewEncoder(w).Encode(clients)
}

func renewCertificate(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	exec.Command("/usr/share/easy-rsa/easyrsa", "renew", p.ByName("name")).Run()
	getCertificates(w, r, p)
}

func deleteCertificate(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var reason RevokeReason
	json.NewDecoder(r.Body).Decode(&reason)
	exec.Command("/usr/share/easy-rsa/easyrsa", "revoke", p.ByName("name"), reason.Reason).Run()
	getCertificates(w, r, p)
}
