// Type definitions for ntlm-client 0.1
// Project: https://github.com/clncln1/node-ntlm-client
// Definitions by: Manuel Borrajo <https://github.com/borrajo>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped

/// <reference types="node"/>

interface NtlmType2 {
    flags: number;
    encoding: string;
    version: number;
    challenge: Buffer;
    targetName: string;
    targetInfo?: {
        parsed: {
            DOMAIN?: string;
            SERVER?: string;
            DNS?: string;
            FQDN?: string;
            PARENT_DNS?: string;
            FLAGS?: number;
            TIMESTAMP?: Buffer;
            CHANNEL_BINDINGS?: Buffer;
        },
        buffer: Buffer;
        timestamp?: Buffer;
        micRequired: boolean;
    };
    /** Whether the server requires a Message Integrity Code in the Type 3 message. */
    micRequired: boolean;
    /** Raw bytes of the decoded Type 2 message, needed to compute the MIC. */
    raw: Buffer;
}

interface NtlmType3Options {
    /** Force NTLMv2 response generation even if the server's Type 2 message doesn't advertise it. */
    forceNtlmV2?: boolean;
    /** Raw base64 Type 1 message string sent for this handshake; required to compute the MIC when the server requires one. */
    type1Message?: string;
    /** 16-byte MD5 hash of the TLS channel binding struct (EPA); omit for plain HTTP or when unavailable. */
    channelBindingValue?: Buffer;
}

declare function createType1Message(workstation: string, domain: string): string;
declare function decodeType2Message(type1Message?: string): NtlmType2;
declare function createType3Message(type2Message: NtlmType2, username: string, password: string, workstation: string, domain: string, options?: NtlmType3Options): string;
declare function createChannelBindingHash(certificateDer: Buffer): Buffer;
export { createType1Message, decodeType2Message, createType3Message, createChannelBindingHash };
