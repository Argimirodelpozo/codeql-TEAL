import codeql.teal.ast.AST

/** The `ed25519verify` opcode: Ed25519 signature verification. */
class Ed25519verifyOpcode extends AstNode instanceof TOpcode_ed25519verify {
    override int getStackDelta() { result = -2 }
    override int getNumberOfConsumedArgs() { result = 3 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `ed25519verify_bare` opcode: Ed25519 bare signature verification. */
class Ed25519verifyBareOpcode extends AstNode instanceof TOpcode_ed25519verify_bare {
    override int getStackDelta() { result = -2 }
    override int getNumberOfConsumedArgs() { result = 3 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `ecdsa_verify` opcode: ECDSA signature verification. */
class EcdsaVerifyOpcode extends AstNode instanceof TOpcode_ecdsa_verify {
    override int getStackDelta() { result = -4 }
    override int getNumberOfConsumedArgs() { result = 5 }
    override int getNumberOfOutputArgs() { result = 1 }
}

/** The `ecdsa_pk_decompress` opcode: ECDSA public key decompression. */
class EcdsaPkDecompressOpcode extends AstNode instanceof TOpcode_ecdsa_pk_decompress {
    override int getStackDelta() { result = 1 }
    override int getNumberOfConsumedArgs() { result = 1 }
    override int getNumberOfOutputArgs() { result = 2 }
}

/** The `ecdsa_pk_recover` opcode: ECDSA public key recovery. */
class EcdsaPkRecoverOpcode extends AstNode instanceof TOpcode_ecdsa_pk_recover {
    override int getStackDelta() { result = -2 }
    override int getNumberOfConsumedArgs() { result = 4 }
    override int getNumberOfOutputArgs() { result = 2 }
}

/** The `vrf_verify` opcode: VRF verification. */
class VrfVerifyOpcode extends AstNode instanceof TOpcode_vrf_verify {
    override int getStackDelta() { result = -1 }
    override int getNumberOfConsumedArgs() { result = 3 }
    override int getNumberOfOutputArgs() { result = 2 }
}
