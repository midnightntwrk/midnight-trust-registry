import { z } from "zod/v4-mini";
export declare enum MidnightNetwork {
    Undeployed = "Undeployed",
    DevNet = "DevNet",
    Testnet = "Testnet",
    Mainnet = "Mainnet",
    Preview = "Preview",
    Preprod = "Preprod",
    Offchain = "Offchain"
}
export declare const ContractAddressHexSchema: z.ZodMiniString<string> & Record<"_zod", Record<"output", string & z.core.$brand<"ContractAddress">>>;
export type ContractAddress = z.infer<typeof ContractAddressHexSchema>;
export declare const OffchainStateHashHexSchema: z.ZodMiniString<string> & Record<"_zod", Record<"output", string & z.core.$brand<"OffchainStateHash">>>;
export type OffchainStateHashHex = z.infer<typeof OffchainStateHashHexSchema>;
export declare function parseContractAddress(input: string): ContractAddress;
export declare function createMidnightDIDString(contractAddress: ContractAddress | OffchainStateHashHex, network: MidnightNetwork): MidnightDIDString;
export declare const MidnightDIDSchema: z.ZodMiniString<string> & Record<"_zod", Record<"output", string & z.core.$brand<"MidnightDID">>>;
export type MidnightDIDString = z.infer<typeof MidnightDIDSchema>;
export declare function parseMidnightDIDString(input: string): MidnightDIDString;
export declare function parseMidnightDID(did: MidnightDIDString): {
    network: MidnightNetwork;
    id: ContractAddress | OffchainStateHashHex;
};
//# sourceMappingURL=midnight.d.ts.map