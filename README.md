# Jack - Jamf API Gateway
Use a Jamf device's certificate to authenticate itself to the Jamf API. No need to set hardcoded API credentials that have unlimited access to other computers. Uses the device certificate Jamf already issues to the device, no need to distribute your own certificates or out of band secrets. 


## Installation
1. Clone the repository `git clone`
2. Copy .env file
```sh
cp .env.sample .env
```
4. Create a Jamf API role
3. `docker compose up`


Self host this in your environment, make it serverless, protect it 
- Create an API user that will execute all the commands
- Needs Read and Write to Computers, Computer extension attributes, File Attachments
- Get the Jamf CA certificate






https://stackoverflow.com/a/73986026/26746068

## Usage
Since Jack is just a gateway to the Jamf API, it accepts the same 
```sh
#! /bin/bash

function get_jamf_device_cert {
    # List all identities (cert+key) in the keychain
    identities=$(security find-identity -v)

    # Extract the certificate names into an array
    cert_names=($(echo "$identities" | grep -oE '"[^"]+"' | tr -d '"'))

    latest_cert_name=""
    latest_enddate=""

    # Loop through each certificate name
    for name in "${cert_names[@]}"; do
        # Get certificate in PEM format
        cert_pem=$(security find-certificate -p -c "$name")

        # Extract the issuer
        issuer=$(echo "$cert_pem" | openssl x509 -noout -issuer | awk -F'CN=' '{split($2, a, ","); print a[1]}')
        
        # Compare if issuer matches common name of Jamf CA 
        [ "$issuer" != "$1" ] && continue

        # Extract the end date
        enddate=$(echo "$cert_pem" | openssl x509 -noout -enddate | awk -F'=' '{print $2}')

        # Check if enddate is not past today
        [ "$(date -jf "%b %d %T %Y %Z" "$enddate" +%s)" -lt "$(date +%s)" ] && continue
        
        # Compare dates and update the latest certificate
        if [[ -z "$latest_enddate" || "$(date -jf "%b %d %T %Y %Z" "$enddate" +%s)" -gt "$(date -jf "%b %d %T %Y %Z" "$latest_enddate" +%s)" ]]; then
            latest_enddate="$enddate"
            latest_cert_name="$name"
        fi
    done

    echo "$latest_cert_name"
}

# change this to be the common name of your Jamf CA
certname=$(get_jamf_device_cert "JSS Built-in Certificate Authority")

# use Secure-Transport backend for Curl, pass name of certificate in keychain 
CURL_SSL_BACKEND=secure-transport curl --cert $certname https://jack-server/JSSResource/computer/id/1001
```

### Available resources
The following Jamf API endpoints are available, format your requests the same as you would to Jamf, just change the base URL to your own. Send requests to the URL with the Jamf
device certificate. 
- JSSResource/computers/id/{id}
- JSSResource/computers/name/{name}
- JSSResource/computers/udid/{udid}
- JSSResource/computers/
