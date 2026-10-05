import axios, { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import * as ntlm from './ntlm';
import * as https from 'https';
import * as http from 'http';
export { AxiosError, AxiosInstance, AxiosRequestConfig, AxiosResponse };

const NTLM_HANDSHAKE_DONE = Symbol('ntlmHandshakeDone');
const NTLM_TYPE1_MESSAGE = Symbol('ntlmType1Message');

/**
 * @property username The username of the user you are authenticating as.
 * @property password The password of the user you are authenticating as.
 * @property domain The domain of the user you are authenticating as.
 * @property workstation The workstation in use. Defaults to the current hostname if undefined.
 * @property forceNtlmV2 Force NTLMv2 response generation even if the server doesn't advertise it; needed by some domain controllers with a strict LmCompatibilityLevel.
 * @property channelBinding Send a TLS channel binding token (Extended Protection for Authentication). Only enable for HTTPS servers that require EPA.
 */
export interface NtlmCredentials {
    readonly username: string;
    readonly password: string;
    readonly domain: string;
    readonly workstation?: string;
    readonly forceNtlmV2?: boolean;
    readonly channelBinding?: boolean;
}

// Best-effort TLS channel binding (EPA); falls back to undefined over plain HTTP or when the certificate is unavailable.
function getChannelBindingValue(err: AxiosError<any, any>): Buffer | undefined {
    try {
        const socket: any = (err.request as any)?.socket;
        if (socket?.encrypted && typeof socket.getPeerCertificate === 'function') {
            const cert = socket.getPeerCertificate();
            if (cert?.raw) {
                return ntlm.createChannelBindingHash(cert.raw);
            }
        }
    } catch {
        // channel binding is optional; ignore failures and proceed without it
    }
    return undefined;
}

/**
* @param credentials An NtlmCredentials object containing the username and password
* @param AxiosConfig The Axios config for the instance you wish to create
*
* @returns This function returns an axios instance configured to use the provided credentials
*/
export function NtlmClient(credentials: NtlmCredentials, AxiosConfig?: AxiosRequestConfig,): AxiosInstance {
    let config: AxiosRequestConfig = AxiosConfig ?? {}

    if (!config.httpAgent) {
        config.httpAgent = new http.Agent({ keepAlive: true });
    }

    if (!config.httpsAgent) {
        config.httpsAgent = new https.Agent({ keepAlive: true });
    }

    const client = axios.create(config);

    client.interceptors.response.use((response) => {
        return response;
    }, async (err: AxiosError<any, any>) => {
        const error: AxiosResponse | undefined = err.response;

        if (error && error.status === 401
            && error.headers['www-authenticate']
            && error.headers['www-authenticate'].includes('NTLM')
            && !(err.config as any)[NTLM_HANDSHAKE_DONE]) {

            // The header may look like this: `Negotiate, NTLM, Basic realm="itsahiddenrealm.example.net"`
            // so extract the 'NTLM' part first
            const ntlmheader = error.headers['www-authenticate'].split(',').find((header: string) => header.match(/ *NTLM/))?.trim() || '';

            // This length check is a hack because SharePoint is awkward and will
            // include the Negotiate option when responding with the T2 message
            // There is nore we could do to ensure we are processing correctly,
            // but this is the easiest option for now
            if (ntlmheader.length < 50) {
                const t1Msg = ntlm.createType1Message(credentials.workstation!, credentials.domain);

                (err.config as any)[NTLM_TYPE1_MESSAGE] = t1Msg;
                error.config.headers["Authorization"] = t1Msg;

            } else {
                const t2Msg = ntlm.decodeType2Message((ntlmheader.match(/^NTLM\s+(.+?)(,|\s+|$)/) || [])[1]);

                const t3Msg = ntlm.createType3Message(t2Msg, credentials.username, credentials.password, credentials.workstation!, credentials.domain, {
                    forceNtlmV2: credentials.forceNtlmV2,
                    type1Message: (err.config as any)[NTLM_TYPE1_MESSAGE],
                    channelBindingValue: credentials.channelBinding ? getChannelBindingValue(err) : undefined
                });

                (err.config as any)[NTLM_HANDSHAKE_DONE] = true;
                error.config.headers["Authorization"] = t3Msg;
            }

            if (error.config.responseType === "stream") {
                const stream: http.IncomingMessage | undefined = err.response?.data;
                // Read Stream is holding HTTP connection open in our
                // TCP socket. Close stream to recycle back to the Agent.
                if (stream && !stream.readableEnded) {
                    await new Promise<void>(resolve => {
                        stream.resume();
                        stream.once('close', resolve);
                    });
                }
            }

            return client(error.config);
        } else {
            throw err;
        }
    });

    return client;
}
