package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Struct for saving the body in the url scan section
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

type VirusTotalFileReport struct {
	Data struct {
		Links struct {
			Self string `json:"link"`
		} `json:"links"`
		Attributes struct {
			Stats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
			}
			Status string `json:"status"` // Scan status
		} `json:"attributes"`
	} `json:"data"`
}

// Struct for getting the id from file upload section
type FileScanID struct {
	Data struct {
		ID string `json:"id"`
	}
}

func analyzeURL(URL string) {

	err := godotenv.Load("APIKEY.env")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	apikey := os.Getenv("APIKEY")

	// Encodes the user submitted URL into base64. This is done because that's what the VT docs said the format of the url needed to be
	var urlID = base64.RawURLEncoding.EncodeToString([]byte(URL))

	// URL for requesting the scan results
	url := "https://www.virustotal.com/api/v3/urls/" + urlID

	// Creates the request to GET the url. The 3rd param is nil because we don't need it for GET requests
	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apikey) // APIKEY goes here

	// Sends the request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	// Closes the body once the function returns
	defer res.Body.Close()
	// Saves the output into a variable called body
	body, _ := io.ReadAll(res.Body)

	// This commented out part saves the body to a json file. If you wish to save the output to json then uncomment this block
	/**/
	file, err := os.Create("urlReport.json")
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
	/**/

	// Gets the body json from the VirusTotalResponse struct | The struct is towards the top of the program
	var urlResults VirusTotalResponse
	// Checks for errors, also for some reason required. If I leave this part out I can't even get data from it
	err = json.Unmarshal(body, &urlResults) // Still new to json stuff so idk what this does besides check for errors when reading the json
	if err != nil {
		fmt.Println("Error parsing json:", err)
		return
	}

	// Outputs the scan results | The only results it shows is the numerical score
	// How many scanners said the url was Harmless, Malicious, Suspicious, or Undetected
	fmt.Println("\nScan results for " + URL)
	fmt.Println("Virus Total URL:", urlResults.Data.Links.Self)
	fmt.Println("Harmless:", urlResults.Data.Attributes.LastAnalysisStats.Harmless)
	fmt.Println("Malicious:", urlResults.Data.Attributes.LastAnalysisStats.Malicious)
	fmt.Println("Suspicious:", urlResults.Data.Attributes.LastAnalysisStats.Suspicious)
	fmt.Println("Undetected:", urlResults.Data.Attributes.LastAnalysisStats.Undetected)

}

// This function takes the url, sends it to virustotal and scans it. The function it calls then retrieves the analysis
// report to be displayed to the user
func scanURL() {

	err := godotenv.Load("APIKEY.env")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	apikey := os.Getenv("APIKEY")

	fmt.Print("URL to scan: ")
	var URL string // User submitted URL to be scanned
	fmt.Scan(&URL)

	// This is the v3 api url for sending requests to VirusTotal
	url := "https://www.virustotal.com/api/v3/urls"

	// For whatever reason this is required to make it work
	// Whenever I try: payload := strings.NewReader(URL) it gives me an error, but when I do url = URL then it works
	url = URL
	payload := strings.NewReader(url) // This reads the url and sets it as the payload for the VT request
	// Also the payload is the url the user submits, while url is the V3 api url

	req, _ := http.NewRequest("POST", url, payload) // Creates a http POST request to Virustotal, using the url and the payload.

	// Required headers by VirusTotal | Not completely sure what they do, but the documentation said these were needed
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apikey) // I do know this one :) it's the apikey header so they can authenticate the API call
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	// This sends the http request with the headers set above
	res, err := http.DefaultClient.Do(req)
	// The error handling isn't "required", but golang prefers me putting this in here
	// This program has error handling everywhere where golang wants there to be, some of it is probably unneccesary
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	// Closes the Body once the function returns
	defer res.Body.Close()

	// Calls the function for getting the scan analysis, also sends the URL variable
	// The url variable is the URL that the user submitted
	analyzeURL(URL)

}

// Function for retrieving the scan results
// scanID is the id gotten from uploading the file | It is a []byte type
func analyzeFile(scanID []byte, path string) {

	err := godotenv.Load("APIKEY.env")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	apikey := os.Getenv("APIKEY")

	// Accessing the FileScanID struct to retrieve the scanID
	var FileUploadBody FileScanID
	err = json.Unmarshal(scanID, &FileUploadBody)
	if err != nil {
		fmt.Println("Error parsing json:", err)
		return
	}

	// url for api calls
	url := "https://www.virustotal.com/api/v3/analyses/" + FileUploadBody.Data.ID

	// Creates the request
	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apikey)
Loop:
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	// This part saves the body to a json file. If you don't want the full scan results then comment this block out
	/**/
	file, err := os.Create("fileReport.json")
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
	/**/

	// Gets the body json from the VirusTotalResponse struct | The struct is towards the top of the program
	var fileResults VirusTotalFileReport
	// Checks for errors, also for some reason required. If I leave this part out I can't even get data from it
	err = json.Unmarshal(body, &fileResults) // Still new to json stuff so idk what this does besides check for errors when reading the json
	if err != nil {
		fmt.Println("Error parsing json:", err)
		return
	}

	// This loop checks the status of the scan.
	for {
		if fileResults.Data.Attributes.Status != "completed" { // If the status of the scan isn't completed then...
			fmt.Println("Waiting for file to finish scanning")
			time.Sleep(5 * time.Second) // Wait 5 seconds then...
			goto Loop                   // Goto a predefined line in this function to check the results of the file | Line 207
		} else {
			break // If the scan status is completed then break out of this loop and print out the results
		}
	}

	// Outputs the scan results | The only results it shows is the numerical score
	// How many scanners said the url was Harmless, Malicious, Suspicious, or Undetected
	fmt.Println("\nScan results for " + path)
	fmt.Println("Virus Total URL:", fileResults.Data.Links.Self)
	fmt.Println("Harmless:", fileResults.Data.Attributes.Stats.Harmless)
	fmt.Println("Malicious:", fileResults.Data.Attributes.Stats.Malicious)
	fmt.Println("Suspicious:", fileResults.Data.Attributes.Stats.Suspicious)
	fmt.Println("Undetected:", fileResults.Data.Attributes.Stats.Undetected)

}

// Function for uploading the file to VirusTotal to be scanned
// The end of this function calls the function that retrieves the report from virustotal
func scanFile(path string) {

	err := godotenv.Load("APIKEY.env")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	apikey := os.Getenv("APIKEY")

	// Opens the file to be used
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Closes the file once the function finishes
	defer file.Close()

	// The following multiple lines are for formatting the file in a way
	// that can be interperetted by the virustotal api url
	// multipart format
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	part, err := writer.CreateFormFile("file", path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = writer.Close()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// url for the api call
	url := "https://www.virustotal.com/api/v3/files"

	// Creates the request, &requestBody is the formatted file
	req, _ := http.NewRequest("POST", url, &requestBody)

	// Headers for the request
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apikey)
	req.Header.Add("content-type", writer.FormDataContentType())

	// Sends the request
	results, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Close the body once the function returns
	defer results.Body.Close()
	// Saves the body to a variable
	body, _ := io.ReadAll(results.Body)

	// Calls the function for retrieving the scan results
	analyzeFile(body, path)

}

func pickFile() {

	cmd := exec.Command("python", "filePicker.py")

	err := cmd.Run()

	if err != nil {
		fmt.Println("Error", err)
		return
	}

	filename := "filepath.txt"

	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	defer f.Close()

	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error", err)
		return
	}

	fmt.Println(string(content))

	scanFile(string(content))

}

func main() {

	// Just a little intro
	fmt.Println("VirusTotal v3 API URL and File scanner")
	fmt.Println("Made by Austin, using Golang")
	fmt.Print("\n")
	fmt.Println("Would you like to scan:\n(1) URL\n(2) FILE")
	fmt.Print("Option: ")

	var scanOption int
	fmt.Scan(&scanOption) // Scan gets input from the last line, &scanOption puts the input into the scanOption variable

	// Function for scanning URL
	if scanOption == 1 {
		scanURL()
	} else if scanOption == 2 { // Function for scanning file
		pickFile()
	} else {
		fmt.Println("\nYou selected an invalid option, please select either 1 or 2.")
		main() // If the user doesn't choose 1 or 2
	}

}
