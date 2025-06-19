// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ErrorMessageVulnerable {
    uint256 public balance;
    
    // VULNERABLE: Generic error message
    function withdraw(uint256 amount) public {
        require(balance >= amount, "");
    }
    
    // VULNERABLE: Generic error message
    function transfer(address to, uint256 amount) public {
        require(balance >= amount, "Error");
    }
    
    // VULNERABLE: Generic error message
    function mint(uint256 amount) public {
        require(amount > 0, "Failed");
    }
    
    // VULNERABLE: Generic error message
    function setBalance(uint256 newBalance) public {
        require(newBalance >= 0, "Invalid");
    }
    
    // VULNERABLE: Generic error message
    function process(uint256 value) public {
        require(value != 0, "Wrong");
    }
} 