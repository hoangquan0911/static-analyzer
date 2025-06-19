// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HardcodedVulnerable {
    // VULNERABLE: Hardcoded values
    uint256 public constant HARDCODED_VALUE = 1000000;
    uint256 public constant HARDCODED_GAS = 3000000;
    uint256 public constant HARDCODED_TIMEOUT = 86400;
    
    // VULNERABLE: Hardcoded addresses
    address public constant HARDCODED_ADDRESS = 0x742d35Cc6634C0532925A3B8D4C9dB96C4B4d8B6;
    address public constant HARDCODED_ORACLE = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    
    // VULNERABLE: Hardcoded values in functions
    function processWithHardcodedValue() public {
        uint256 result = 5000000; // Hardcoded magic number
    }
    
    // VULNERABLE: Hardcoded gas limit
    function callWithHardcodedGas() public {
        // Hardcoded gas limit
    }
    
    // VULNERABLE: Hardcoded timeout
    function timeoutWithHardcodedValue() public {
        uint256 timeout = 3600; // Hardcoded timeout
    }
    
    // VULNERABLE: Hardcoded decimals
    function calculateWithHardcodedDecimals() public {
        uint256 decimals = 18; // Hardcoded decimals
    }
} 