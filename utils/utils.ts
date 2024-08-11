import * as crypto from 'crypto'

const regexPatterns = [
    /^(\/JSSResource\/computers\/(id)\/)(\d+)$/,
    /^(\/JSSResource\/computers\/(name)\/)([\w-]+)$/,
    /^(\/JSSResource\/computers\/(serialnumber)\/)(\w+)$/,
    /^(\/JSSResource\/computers\/(udid)\/)([\w-]+)$/,
    /^(\/JSSResource\/computers\/(macaddress)\/)([\w:]+)$/,
    /^(\/JSSResource\/fileuploads\/computer\/)(id)\/(\d+)$/,
    /^(\/JSSResource\/fileuploads\/computer\/)(name)\/([\w-]+)$/
];

// check if the client certificate is signed by the Jamf CA
export const isValidCert = (client, ca: Buffer | string): boolean => {
    // cannot use req.client.authorized because the client certificate
    // does not have keyEncipherment key usage
    const jamfx509 = new crypto.X509Certificate(ca);
    const x509 = new crypto.X509Certificate(client);
    
    return x509.checkIssued(jamfx509);
}

export const getPathDetails = (path: string): {resource: string, lookupType: string, lookupValue: string} => {
    for (const regex of regexPatterns) {
        const match = path.match(regex);
        if (match) {
            return {
                "resource": match[1],
                "lookupType": match[2],
                "lookupValue": match[3]
            }
        }
    }

    return {
        "resource": "",
        "lookupType": "",
        "lookupValue": ""
    }
}

export const isValidMethodPath = (method: string, path: string): boolean => {
    const validPaths = {
        '/JSSResource/computers/id/':               ['GET', 'PUT'],
        '/JSSResource/computers/name/':             ['GET', 'PUT'],
        '/JSSResource/computers/serialnumber/':     ['GET', 'PUT'],
        '/JSSResource/computers/udid/':             ['GET', 'PUT'],
        '/JSSResource/computers/macaddress/':       ['GET', 'PUT'],
        '/JSSResource/fileuploads/computer/id':     ['PUT'],
        '/JSSResource/fileuploads/computer/name':   ['PUT']
    };
    return validPaths[path] ? validPaths[path].includes(method) : false;
}
