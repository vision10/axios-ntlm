# Axios-NTLM

This is a helper library for NTLM Authentication using the [Axios](https://github.com/axios/axios) HTTP library on Node. It attaches interceptors to an axios instance to authenticate using NTLM for any resources that offer it.

> This package is the maintained continuation of [`axios-ntlm`](https://www.npmjs.com/package/axios-ntlm), published as `axios-ntlm2`. To migrate, replace the dependency and update your imports; the API is unchanged.

```
npm install axios-ntlm2
```

## Examples

### Basic example

This example will create you a brand new axios instance you can utilise the same as any other axios instance

```ts

import { NtlmClient, NtlmCredentials } from 'axios-ntlm2';

(async () => {

    let credentials: NtlmCredentials = {
        username: 'username',
        password: "password",
        domain: 'domain'
    }

    let client = NtlmClient(credentials)

    try {
        let resp = await client({
            url: 'https://protected.site.example.com',
            method: 'get'
        });
        console.log(resp.data);
    }
    catch (err) {
        console.log(err)
        console.log("Failed")
    }

})()

```
### With a custom Axios config

This shows how to pass in an axios config in the same way that you would when setting up any other axios instance. 

Note: If doing this, be aware that http(s)Agents need to be attached to keep the connection alive. If there are none attached already, they will be added. If you are providing your own then you will need to set this up.

```ts
import { AxiosRequestConfig } from 'axios';
import { NtlmClient, NtlmCredentials } from 'axios-ntlm2';

(async () => {
    
    let credentials: NtlmCredentials = {
        username: 'username',
        password: "password",
        domain: 'domain'
    }

    let config: AxiosRequestConfig = {
        baseURL: 'https://protected.site.example.com',
        method: 'get'
    }

    let client = NtlmClient(credentials, config)

    try {
        let resp = await client.get('/api/123')
        console.log(resp);
    }
    catch (err) {
        console.log(err)
        console.log("Failed")
    }

})()

```

## NTLMv2

NTLMv2 is used automatically when the server's challenge asks for extended session security, which most modern Windows servers do. The NTLMv2 responses are checked against the test vectors in Microsoft's [MS-NLMP specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) (section 4.2.4). When the server sends a timestamp, the client uses that timestamp instead of its own clock. This prevents failures caused by clock differences between the client and server.

### Credential options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `username` | `string` | | The user to authenticate as. |
| `password` | `string` | | The user's password. |
| `domain` | `string` | | The user's domain. |
| `workstation` | `string` | current hostname | The workstation name sent to the server. |
| `forceNtlmV2` | `boolean` | `false` | Always send an NTLMv2 response, even if the server does not advertise extended session security. Use this when a domain controller is configured to refuse NTLMv1 (`LmCompatibilityLevel` 3 or higher) and authentication fails without it. |
| `channelBinding` | `boolean` | `false` | **Experimental.** Sends a TLS channel binding token for servers that enforce Extended Protection for Authentication (EPA) over HTTPS. The token is derived with SHA-256, so it is only correct for certificates signed with SHA-256 or weaker. Leave this disabled unless EPA is enforced and authentication fails without it. |

```ts
import { NtlmClient, NtlmCredentials } from 'axios-ntlm2';

const credentials: NtlmCredentials = {
    username: 'username',
    password: 'password',
    domain: 'domain',
    forceNtlmV2: true
}

const client = NtlmClient(credentials)
```