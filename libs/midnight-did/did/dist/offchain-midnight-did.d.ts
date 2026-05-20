import { createOffchainMidnightDidDocumentMetadata, type OffchainMidnightDIDState, type ParsedPortableOffchainMidnightDIDUrl } from "@midnight-ntwrk/midnight-did-domain";
import { type MidnightDIDDocument } from "./midnight-did-document.js";
export type ResolvedPortableOffchainMidnightDID = {
    readonly did: string;
    readonly parsed: ParsedPortableOffchainMidnightDIDUrl;
    readonly state: OffchainMidnightDIDState;
    readonly didDocument: MidnightDIDDocument;
    readonly didDocumentMetadata: ReturnType<typeof createOffchainMidnightDidDocumentMetadata>;
};
export declare const resolvePortableOffchainMidnightDID: (input: string) => ResolvedPortableOffchainMidnightDID;
export declare const assertOffchainMidnightDID: (did: string) => string;
//# sourceMappingURL=offchain-midnight-did.d.ts.map