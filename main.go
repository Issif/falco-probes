package main

import (
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/dustin/go-humanize"
)

const source = "https://falco-distribution.s3-eu-west-1.amazonaws.com/?list-type=2&prefix=driver"
const download = "https://download.falco.org/"

type ListBucketResult struct {
	XMLName               xml.Name  `xml:"ListBucketResult"`
	Contents              []Content `xml:"Contents"`
	NextContinuationToken string    `xml:"NextContinuationToken"`
	IsTruncated           string    `xml:"IsTruncated"`
}

type Content struct {
	Lib          string `json:"lib"`
	Arch         string `json:"arch"`
	Kind         string `json:"kind"`
	Target       string `json:"target"`
	Key          string `xml:"Key" json:"name"`
	Download     string `json:"download"`
	SizeBytes    int    `xml:"Size" json:"sizebytes"`
	Size         string `xml:"SizeString" json:"size"`
	LastModified string `xml:"LastModified" json:"lastmodified"`
}

type List struct {
	Libs    []string `json:"lib"`
	Archs   []string `json:"arch"`
	Kinds   []string `json:"kind"`
	Targets []string `json:"target"`
}

var (
	list  List
	files map[string][]Content
)

func init() {
	files = make(map[string][]Content)
	if err := os.RemoveAll("./data"); err != nil {
		log.Fatal(err)
	}
}

func main() {
	fetchXML("")
	for i, j := range files {
		if err := os.MkdirAll(filepath.Dir(i), 0754); err != nil {
			log.Fatal(err)
		}
		f, err := json.Marshal(j)
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile(i, f, 0755)
		if err != nil {
			log.Fatal(err)
		}
	}
	l := List{
		Libs:    removeDuplicateStr(list.Libs),
		Archs:   removeDuplicateStr(list.Archs),
		Kinds:   removeDuplicateStr(list.Kinds),
		Targets: removeDuplicateStr(list.Targets),
	}
	f, err := json.Marshal(l)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("./data/list.json", f, 0755)
	if err != nil {
		log.Fatal(err)
	}
}

func fetchXML(token string) {
	url := source
	if token != "" {
		url += "&continuation-token=" + neturl.QueryEscape(token)
	}

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	byteValue, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	var listBucket ListBucketResult
	if err := xml.Unmarshal(byteValue, &listBucket); err != nil {
		log.Fatalln(err)
	}

	for _, i := range listBucket.Contents {
		k := i.Key
		var key, lib, arch, kind, target string
		s := strings.Split(k, "/")
		lib = s[1]
		switch len(s) {
		case 3:
			arch = "x86_64"
			key = s[2]
		case 4:
			arch = s[2]
			key = s[3]
		default:
			continue
		}
		target = strings.Split(key, "_")[1]
		switch filepath.Ext(key) {
		case ".o":
			kind = "ebpf"
		case ".ko":
			kind = "kmod"
		default:
			kind = "unknown"
		}
		list.Libs = append(list.Libs, lib)
		list.Archs = append(list.Archs, arch)
		list.Kinds = append(list.Kinds, kind)
		list.Targets = append(list.Targets, target)
		files["./data/"+lib+"/"+arch+"/"+target+"/"+kind+".json"] = append(files["./data/"+lib+"/"+arch+"/"+target+"/"+kind+".json"], Content{
			Lib:          lib,
			Arch:         arch,
			Key:          key,
			Target:       target,
			SizeBytes:    i.SizeBytes,
			Size:         humanize.Bytes(uint64(i.SizeBytes)),
			LastModified: i.LastModified,
			Kind:         kind,
			Download:     download + k,
		})
	}

	if listBucket.IsTruncated == "true" {
		fetchXML(listBucket.NextContinuationToken)
	}
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
