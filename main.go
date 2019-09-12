package main

import (
	"bufio"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
)

var filePath = "./input/list.html"

type probe struct {
	FalcoVersion  string `json:"falco_version"`
	Architecture  string `json:"architecture"`
	KervelVersion string `json:"kernel_version"`
	Hash          string `json:"hash"`
	CreationDate  string `json:"creation_date"`
	Size          string `json:"size"`
	Link          string `json:"link"`
}

func main() {
	probes := make(map[string][]probe)
	// var fVersions []string

	regx := regexp.MustCompile("\"falco-probe-.*\"")

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// match := regx.FindAllString(scanner.Text(), -1)
		match := regx.FindStringSubmatch(scanner.Text())
		if len(match) != 0 {
			r := strings.Split(scanner.Text(), " ")
			// fmt.Printf("%#v\n", r)
			s := strings.Split(match[0][1:len(match[0])-4], "-")
			p := probe{
				FalcoVersion:  s[2],
				Architecture:  s[3],
				Hash:          s[len(s)-1],
				CreationDate:  r[8] + " " + r[9],
				Size:          r[11],
				KervelVersion: "",
				Link:          "https://s3.amazonaws.com/download.draios.com/stable/sysdig-probe-binaries/" + match[0][1:len(match[0])-1],
			}
			for i := 4; i < len(s)-1; i++ {
				p.KervelVersion += s[i] + "-"
			}
			p.KervelVersion = p.KervelVersion[:len(p.KervelVersion)-1]
			probes[p.FalcoVersion] = append(probes[p.FalcoVersion], p)
		}
	}
	v := make(map[string]string)
	for i := range probes {
		v[i] = ""
		j, _ := json.Marshal(probes[i])
		err := ioutil.WriteFile("./data/"+i+".json", j, 0755)
		if err != nil {
			log.Fatal(err)
		}
	}

	f, err := os.Create("index.html")
	defer f.Close()
	if err != nil {
		log.Fatalf("create file: %v", err)
	}

	t, err := template.ParseFiles("index.gotemplate")
	if err != nil {
		log.Fatalf("parse : %v", err)
	}

	err = t.Execute(f, v)
	if err != nil {
		log.Fatalf("create file: %v", err)
	}

}
