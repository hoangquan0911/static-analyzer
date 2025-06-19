// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EventsVulnerable {
    uint256 public balance;
    address public owner;
    
    // VULNERABLE: Missing event emission
    function transfer(address to, uint256 amount) public {
        balance -= amount;
        // Missing Transfer event
    }
    
    // VULNERABLE: Missing event emission
    function mint(address to, uint256 amount) public {
        balance += amount;
        // Missing Mint event
    }
    
    // VULNERABLE: Missing event emission
    function withdraw(uint256 amount) public {
        balance -= amount;
        payable(msg.sender).transfer(amount);
        // Missing Withdraw event
    }
    
    // VULNERABLE: Missing event emission
    function setOwner(address newOwner) public {
        owner = newOwner;
        // Missing OwnershipTransferred event
    }
    
    // VULNERABLE: Missing event emission
    function updateBalance(uint256 newBalance) public {
        balance = newBalance;
        // Missing BalanceUpdated event
    }
} 