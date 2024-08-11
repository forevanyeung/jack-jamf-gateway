# Computer API Proxy
Use a Jamf device's certificate to authenticate itself to the Jamf API. No need to set hardcoded API credentials that have unlimited access to other computers. Uses the device certificate Jamf already issues to the device, no need to distribute your own certificates or out of band secrets. 



Self host this in your environment, make it serverless, protect it 
- Create an API user that will execute all the commands
- Needs Read and Write to Computers, Computer extension attributes, File Attachments
- Get the Jamf CA certificate



The following Jamf API endpoints are available, format your requests the same as you would to Jamf, just change the base URL to your own. Send requests to the URL with the Jamf
device certificate. 


https://stackoverflow.com/a/73986026/26746068


```sh
# get name of certificate from security

# use Secure-Transport backend for Curl, pass name of certificate in keychain 
CURL_SSL_BACKEND=secure-transport curl --cert
```
