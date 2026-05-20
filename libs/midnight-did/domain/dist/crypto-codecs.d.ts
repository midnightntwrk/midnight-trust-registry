import { z } from "zod/v4-mini";
export declare const decodeFieldElement: (s: string) => bigint;
export declare const encodeFieldElement: (v: bigint) => string;
export declare const FieldCodec: z.ZodMiniCodec<z.ZodMiniString<string>, z.ZodMiniBigInt<bigint>>;
//# sourceMappingURL=crypto-codecs.d.ts.map