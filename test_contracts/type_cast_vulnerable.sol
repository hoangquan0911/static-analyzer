// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TypeCastVulnerable {
    uint256 public value;
    
    // VULNERABLE: Unsafe type casting
    function unsafeCast(uint256 input) public {
        uint8 smallValue = uint8(input); // Truncation possible
        value = smallValue;
    }
    
    // VULNERABLE: Unsafe type casting
    function unsafeCast16(uint256 input) public {
        uint16 smallValue = uint16(input); // Truncation possible
        value = smallValue;
    }
    
    // VULNERABLE: Unsafe type casting
    function unsafeCast32(uint256 input) public {
        uint32 smallValue = uint32(input); // Truncation possible
        value = smallValue;
    }
    
    // VULNERABLE: Unsafe type casting
    function unsafeCast64(uint256 input) public {
        uint64 smallValue = uint64(input); // Truncation possible
        value = smallValue;
    }
    
    // VULNERABLE: Unsafe type casting
    function unsafeCast128(uint256 input) public {
        uint128 smallValue = uint128(input); // Truncation possible
        value = smallValue;
    }
} 