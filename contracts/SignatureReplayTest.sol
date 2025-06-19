// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SignatureReplayTest {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: No replay protection
    function withdrawWithSignature(
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // Create the message hash
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        
        // Recover the signer
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        
        // Check if signer is authorized (but no replay protection!)
        require(signer == address(0x123), "Invalid signature");
        
        // Transfer funds
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // SAFE: With replay protection
    mapping(bytes32 => bool) public usedHashes;
    
    function withdrawWithSignatureSafe(
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // Create the message hash
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        
        // Check if this hash has been used before
        require(!usedHashes[ethSignedMessageHash], "Signature already used");
        
        // Mark as used
        usedHashes[ethSignedMessageHash] = true;
        
        // Recover the signer
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        
        // Check if signer is authorized
        require(signer == address(0x123), "Invalid signature");
        
        // Transfer funds
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // Another vulnerable pattern using ECDSA library
    function withdrawWithECDSA(
        uint256 amount,
        bytes memory signature
    ) public {
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        
        // Using ECDSA.recover without replay protection
        address signer = ECDSA.recover(ethSignedMessageHash, signature);
        
        require(signer == address(0x123), "Invalid signature");
        
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

// Mock ECDSA library for testing
library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Mock implementation
        return address(0);
    }
} 