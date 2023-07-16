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

func (c Client) withLinks() Client {
	if c.Revoked != "" {
		return c
	}
	c.Links = []Link{
		{Rel: "revoke", Method: "DELETE", Path: fmt.Sprintf("/clients/%s/revoke", c.Name)},
	}
	return c
}

func main() {
	r := httprouter.New()
	r.POST("/ca-certs/common", postCommonCACert)
	r.POST("/ca-certs/org", postOrgCACert)
	r.POST("/servers/:name", postServers)
	r.POST("/clients/:name", postClients)
	r.DELETE("/clients/:name", deleteClients)
	r.GET("/clients", getClients)
	log.Fatal(http.ListenAndServe(":8080", r))
}

func postCommonCACert(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// ...
}

func postOrgCACert(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// ...
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
	exec.Command("/usr/share/easy-rsa/easyrsa", "revoke", p.ByName("name"), "nopass").Run()
	getClients(w, r, p)
}

func getClients(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	file, err := os.Open("index.txt")
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
