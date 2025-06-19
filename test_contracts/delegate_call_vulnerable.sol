// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DelegateCallVulnerable {
    address public implementation;
    uint256 public value;
    
    // VULNERABLE: Delegate call without proper validation
    function upgrade(address newImplementation) public {
        implementation = newImplementation;
    }
    
    // VULNERABLE: Delegate call to arbitrary address
    function execute(bytes memory data) public {
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegate call failed");
    }
    
    // VULNERABLE: Delegate call without storage layout check
    function setValue(uint256 newValue) public {
        value = newValue;
    }
    
    // VULNERABLE: Delegate call in fallback
    fallback() external {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "Fallback delegate call failed");
    }
} 