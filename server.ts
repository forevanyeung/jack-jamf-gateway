import * as fs from 'fs'
import * as https from 'https'
import { getPathDetails, isValidMethodPath, isValidCert } from './utils/utils'
import { certMatchesComputer, proxyIncommingMessageWithJamAuth } from './utils/jamf'

const PORT = process.env.PORT || 9443;
const HTTPS_CERT = process.env.HTTPS_CERT || fs.readFileSync('certificates/server.crt');
const HTTPS_KEY = process.env.HTTPS_KEY || fs.readFileSync('certificates/server.key');
const JAMF_CA_CERT = process.env.JAMF_CA_CERT || fs.readFileSync('certificates/jamfca.crt');

const app = async (req, res) => {
    try {
        console.log('Request received')
        console.log(req.method, req.url);

        // check if the client certificate is signed by the Jamf CA
        // cannot use req.client.authorized because the client certificate
        // does not have keyEncipherment key usage
        const peerCert = req.socket.getPeerCertificate();
        if (Object.keys(peerCert).length === 0 || !isValidCert(peerCert.raw, JAMF_CA_CERT)) {
            console.error("401 Missing or invalid peer certificate not signed by CA")
            res.writeHead(401);
            return res.end('Unauthorized');
        }

        // extracts details from the path
        const {resource, lookupType, lookupValue} = getPathDetails(req.url);
        console.log("Extracted details from path", resource, lookupType, lookupValue)

        // check if the path is one of the valid JAMF api paths
        if (!isValidMethodPath(req.method, resource)) {
            console.error("404 Invalid method or resource path")
            res.writeHead(404);
            return res.end('Not Found');
        }

        // confirm certificate belongs to the computer record
        if (! await certMatchesComputer(lookupType, lookupValue, peerCert.subject.CN)) {
            console.error("401 Certificate does not belong to the computer record")
            res.writeHead(401);
            return res.end('Unauthorized');
        }

        // pass the request to the JAMF server
        // be careful returning the response to the client, may contain sensitive 
        // information
        const proxyResponse = await proxyIncommingMessageWithJamAuth(req);
        const body = await proxyResponse.text();

        res.writeHead(proxyResponse.status, Object.fromEntries(proxyResponse.headers));
        res.end(body);
    } catch (error) {
        console.error(error);
        res.writeHead(500);
        res.end('Internal Server Error');
    }
};

const options = {
    cert: HTTPS_CERT,
    key: HTTPS_KEY,
    requestCert: true,
    rejectUnauthorized: false,
    ca: JAMF_CA_CERT
};

https.createServer(options, app).listen(PORT, () => {
    console.log(`Server running at https://localhost:${PORT}/`)
});
