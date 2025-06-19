// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Mock ECDSA library for testing
library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Mock implementation
        return address(0);
    }
}

contract ComprehensiveSignatureTest {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Basic ecrecover without replay protection
    function withdrawWithEcrecover(
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        require(signer == address(0x123), "Invalid signature");
        
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // VULNERABLE: Custom signature verification without replay protection
    function withdrawWithCustomVerify(
        uint256 amount,
        bytes memory signature
    ) public {
        bool isValid = verifySignature(msg.sender, amount, signature);
        require(isValid, "Invalid signature");
        
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // VULNERABLE: EIP-712 without proper domain separator
    function withdrawWithEIP712(
        uint256 amount,
        bytes memory signature
    ) public {
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("MyContract")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
        
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Withdraw(address user,uint256 amount)"),
            msg.sender,
            amount
        ));
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = ECDSA.recover(digest, signature);
        require(signer == address(0x123), "Invalid signature");
        
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // VULNERABLE: Permit function without nonce tracking
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(deadline >= block.timestamp, "Permit expired");
        
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            owner,
            spender,
            value,
            0, // No nonce tracking!
            deadline
        ));
        
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        
        // Process the permit...
    }
    
    // VULNERABLE: Signature verification in loop
    function batchWithdraw(
        uint256[] memory amounts,
        bytes[] memory signatures
    ) public {
        for (uint i = 0; i < amounts.length; i++) {
            bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amounts[i]));
            bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
            
            address signer = ECDSA.recover(ethSignedMessageHash, signatures[i]);
            require(signer == address(0x123), "Invalid signature");
            
            balances[msg.sender] -= amounts[i];
            payable(msg.sender).transfer(amounts[i]);
        }
    }
    
    // SAFE: With proper replay protection
    mapping(bytes32 => bool) public usedHashes;
    
    function withdrawSafe(
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        
        require(!usedHashes[ethSignedMessageHash], "Signature already used");
        usedHashes[ethSignedMessageHash] = true;
        
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        require(signer == address(0x123), "Invalid signature");
        
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // Helper functions
    function verifySignature(address user, uint256 amount, bytes memory signature) internal pure returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(user, amount));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        
        address signer = ECDSA.recover(ethSignedMessageHash, signature);
        return signer == address(0x123);
    }
    
    function DOMAIN_SEPARATOR() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("MyContract")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }
} 