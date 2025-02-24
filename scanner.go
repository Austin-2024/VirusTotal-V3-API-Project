package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type VirusTotalResponse struct {
	Data struct {
		Links struct {
			Self string `json:"self"`
		}
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func analyzeURL(URL string) {

	var urlID = base64.RawURLEncoding.EncodeToString([]byte(URL))

	url := "https://www.virustotal.com/api/v3/urls/" + urlID

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", "APIKEY")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	/*
		file, err := os.Create("body.json")
		if err != nil {
			fmt.Println(err)
			return
		}

		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			fmt.Println("Failed to write to file", err)
			return
		}
	*/

	var urlResults VirusTotalResponse
	err = json.Unmarshal(body, &urlResults)
	if err != nil {
		fmt.Println("Error parsing json:", err)
		return
	}

	fmt.Println("\nScan results for " + URL)
	fmt.Println("Virus Total URL:", urlResults.Data.Links.Self)
	fmt.Println("Harmless:", urlResults.Data.Attributes.LastAnalysisStats.Harmless)
	fmt.Println("Malicious:", urlResults.Data.Attributes.LastAnalysisStats.Malicious)
	fmt.Println("Suspicious:", urlResults.Data.Attributes.LastAnalysisStats.Suspicious)
	fmt.Println("Undetected:", urlResults.Data.Attributes.LastAnalysisStats.Undetected)

}

func scanURL() {
	fmt.Print("URL to scan: ")
	var URL string
	fmt.Scan(&URL)

	url := "https://www.virustotal.com/api/v3/urls"

	url = URL
	payload := strings.NewReader(url)

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", "APIKEY")
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	defer res.Body.Close()

	analyzeURL(URL)
	return

}

func scanFile() {

	cmd := exec.Command("python", "filePicker.py")

	err := cmd.Run()

	if err != nil {
		fmt.Println("Error", err)
		return
	}

	filename := "filepath.txt"

	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error", err)
		return
	}

	fmt.Println(content)

}

func main() {

	fmt.Println("VirusTotal v3 API URL and File scanner")
	fmt.Println("Made by Austin, using Golang")
	fmt.Print("\n")
	fmt.Println("Would you like to scan:\n(1) URL\n(2) FILE")
	fmt.Print("Option: ")

	var scanOption int
	fmt.Scan(&scanOption)

	if scanOption == 1 {
		scanURL()
	} else if scanOption == 2 {
		scanFile()
	} else {
		fmt.Println("\nYou selected an invalid option, please select either 1 or 2.")
		main()
	}

}
