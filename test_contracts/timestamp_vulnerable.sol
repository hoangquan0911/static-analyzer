// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimestampVulnerable {
    uint256 public lastUpdate;
    uint256 public randomNumber;
    
    // VULNERABLE: Using block.timestamp for randomness
    function generateRandom() public {
        randomNumber = uint256(keccak256(abi.encodePacked(block.timestamp)));
    }
    
    // VULNERABLE: Using block.timestamp for time-based logic
    function canUpdate() public view returns (bool) {
        return block.timestamp >= lastUpdate + 1 hours;
    }
    
    // VULNERABLE: Using block.timestamp for deadline
    function processPayment(uint256 deadline) public {
        require(block.timestamp <= deadline, "Payment expired");
        // Process payment
    }
    
    // VULNERABLE: Using block.timestamp for time window
    function timeWindow() public view returns (bool) {
        return block.timestamp % 86400 < 43200; // First half of day
    }
} 