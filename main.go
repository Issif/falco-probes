package main

import (
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"log"
	"net/http"
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
	Key          string `xml:"Key" json:"name"`
	Download     string `json:"download"`
	Size         int    `xml:"Size"`
	SizeString   string `json:"size"`
	LastModified string `xml:"LastModified" json:"lastmodified"`
}

var drivers []Content

func main() {
	fetchXML("")

	j, err := json.Marshal(drivers)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("./data/list.json", j, 0755)
	if err != nil {
		log.Fatal(err)
	}
}

func fetchXML(after string) {
	url := source
	if after != "" {
		url += "&start-after=" + after
	}

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	byteValue, _ := ioutil.ReadAll(resp.Body)

	var list ListBucketResult
	xml.Unmarshal(byteValue, &list)

	if list.Contents[len(list.Contents)-1].Key == after {
		return
	}

	for i := 0; i < len(list.Contents); i++ {
		k := list.Contents[i].Key
		var key, lib, arch, kind string
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
		switch filepath.Ext(key) {
		case ".o":
			kind = "ebpf"
		case ".ko":
			kind = "kmod"
		default:
			kind = "unknown"
		}
		drivers = append(drivers, Content{
			Lib:          lib,
			Arch:         arch,
			Key:          key,
			SizeString:   humanize.Bytes(uint64(list.Contents[i].Size)),
			LastModified: list.Contents[i].LastModified,
			Kind:         kind,
			Download:     download + k,
		})
	}

	fetchXML(list.Contents[len(list.Contents)-1].Key)
}
