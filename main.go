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

type RevokeReason struct {
	Reason string `json:"reason"`
}

type CaCert struct {
	Type string `json:"type"`
}

func (c Client) withLinks() Client {
	if c.Revoked != "" {
		return c
	}
	c.Links = []Link{
		{Rel: "revoke", Method: "DELETE", Path: fmt.Sprintf("/clients/%s", c.Name)},
	}
	return c
}

func main() {
	r := httprouter.New()
	r.GET("/", index)
	r.POST("/ca-certs", postCACert)
	r.POST("/servers/:name", postServers)
	r.POST("/clients/:name", postClients)
	r.DELETE("/clients/:name", deleteClients)
	r.GET("/clients", getClients)
	log.Fatal(http.ListenAndServe(":8080", r))
}

func index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	http.ServeFile(w, r, "/var/www/index.html")
}

func postCACert(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if _, err := os.Stat("/usr/share/easy-rsa/pki/ca.crt"); err == nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	var cert CaCert
	json.NewDecoder(r.Body).Decode(&cert)
	if cert.Type == "common" {
		exec.Command("/usr/share/easy-rsa/easyrsa", "build-ca", "nopass").Run()
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusNotImplemented)
}

func postServers(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	exec.Command("/usr/share/easy-rsa/easyrsa", "build-server-full", p.ByName("name"), "nopass").Run()
	getClients(w, r, p)
}

func postClients(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	exec.Command("/usr/share/easy-rsa/easyrsa", "build-client-full", p.ByName("name"), "nopass").Run()
	getClients(w, r, p)
}

func deleteClients(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	var reason RevokeReason
	json.NewDecoder(r.Body).Decode(&reason)
	exec.Command("/usr/share/easy-rsa/easyrsa", "revoke", p.ByName("name"), reason.Reason).Run()
	getClients(w, r, p)
}

func getClients(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	file, err := os.Open("/usr/share/easy-rsa/pki/index.txt")
	if err != nil {
		log.Fatal(err)
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
