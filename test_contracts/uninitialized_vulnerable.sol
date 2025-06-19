// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UninitializedVulnerable {
    uint256 public value;
    address public owner;
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Uninitialized storage variable
    uint256 public uninitializedValue;
    
    // VULNERABLE: Uninitialized storage variable
    address public uninitializedAddress;
    
    // VULNERABLE: Uninitialized storage variable
    mapping(address => uint256) public uninitializedMapping;
    
    constructor() {
        value = 100;
        owner = msg.sender;
        balances[msg.sender] = 1000;
    }
    
    // VULNERABLE: Using uninitialized variable
    function getUninitializedValue() public view returns (uint256) {
        return uninitializedValue; // Will return 0
    }
    
    // VULNERABLE: Using uninitialized variable
    function getUninitializedAddress() public view returns (address) {
        return uninitializedAddress; // Will return address(0)
    }
    
    // VULNERABLE: Using uninitialized mapping
    function getUninitializedBalance(address user) public view returns (uint256) {
        return uninitializedMapping[user]; // Will return 0
    }
} 