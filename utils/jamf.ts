import { IncomingMessage } from "http"

const JSS_URL = process.env.JSS_URL || "";
const JSS_USERNAME = process.env.JSS_USERNAME || "";
const JSS_PASSWORD = process.env.JSS_PASSWORD || "";

let bearerToken = ""
let bearerExpiresAt = 0

const getBearerToken = async (url: string, username: string, password: string) : Promise<string> => {
// if token is not set or expired, fetch a new one
    if (!bearerToken || bearerExpiresAt < Date.now()) {
        console.log("Bearer token not set or expired. Fetching new one.")

        try {
            const response = await fetch(`${url}/api/v1/auth/token`, {
                method: 'POST',
                headers: {
                    authorization: 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64')
                }
            })

            const data = await response.json()
            bearerToken = data.token
            bearerExpiresAt = data.expires
    
            console.log("Bearer token fetched. Expires at: " + bearerExpiresAt)
        } catch (error) {
            console.error(error)
        }
    }

    return bearerToken
}

const fetchWithJamfAuth = async (path: string, init?: RequestInit): Promise<Response> => {
    // get the headers from the request
    let headers = Object.fromEntries(new Headers(init?.headers) ?? [])

    // add authentication to the request
    const token = await getBearerToken(JSS_URL, JSS_USERNAME, JSS_PASSWORD)
    headers['authorization'] = 'Bearer ' + token
    headers['user-agent'] = 'ComputerAPIProxy/1.0 ' + headers['User-Agent']

    // send the request and return the response
    return fetch(`${JSS_URL}${path}`, {...init, headers})
}

const getJamfComputer = async (lookupType: string, lookupValue: string) => {
    try {
        const response = await fetchWithJamfAuth(`/JSSResource/computers/${lookupType}/${lookupValue}`, {
            headers: { 'Accept': 'application/json' }
        })

        if (!response.ok) {
            console.error(`Failed to fetch computer with ${lookupType} ${lookupValue}`)
            return
        }

        const data = response.json()

        return data
    } catch (error) {
        console.error(error)
    }
}

export const certMatchesComputer = async (lookupType: string, lookupValue: string, certName: string) : Promise<boolean> => {
    const computer = await getJamfComputer(lookupType, lookupValue)
    if (!computer) {
        return false
    }

    const certificates = computer.computer.certificates

    const matchFound = certificates.some(cert => cert.common_name === certName);

    return matchFound
}

export const proxyIncommingMessageWithJamAuth = async (req: IncomingMessage) => {
    // this should never happen, but we need to check for type safety
    if (req.url === undefined) {
        throw new Error('Request URL is undefined')
    }

    // https://stackoverflow.com/a/78849544
    const headers = new Headers()
    for (const [key, value] of Object.entries(req.headers)) {
        if (Array.isArray(value)) {
            value.forEach((v) => headers.append(key, v));
        } else if (value !== undefined) {
            headers.set(key, value);
        }
    }

    const options: RequestInit = {
        method: req.method,
        headers: headers,
        body: req.method !== 'GET' && req.method !== 'HEAD' ? await get_request_body(req) : null,
        // referrer: '',
        // referrerPolicy: '',
        // mode: 'cors',
        // credentials: 'omit',
        // cache: 'default',
        // redirect: 'follow',
        // integrity: '',
        // keepalive: false,
        // signal: null,
        // duplex: 'half',
        // priority: 'auto',
        // window: null
    }

    return fetchWithJamfAuth(req.url, options)
}

const get_request_body = (req: IncomingMessage): Promise<Buffer> => {
    return new Promise<Buffer>((resolve, reject) => {
        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => {
            chunks.push(chunk);
        });
        req.on('end', () => {
            resolve(Buffer.concat(chunks));
        });
        req.on('error', (err) => {
            reject(err);
        });
    });
}
