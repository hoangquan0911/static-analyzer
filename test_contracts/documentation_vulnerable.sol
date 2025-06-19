// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DocumentationVulnerable {
    uint256 public balance;
    address public owner;
    
    // VULNERABLE: Missing NatSpec documentation
    function transfer(address to, uint256 amount) public {
        balance -= amount;
    }
    
    // VULNERABLE: Missing NatSpec documentation
    function mint(address to, uint256 amount) public {
        balance += amount;
    }
    
    // VULNERABLE: Missing NatSpec documentation
    function withdraw(uint256 amount) public {
        balance -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // VULNERABLE: Missing NatSpec documentation
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
    
    // VULNERABLE: Missing NatSpec documentation
    function updateBalance(uint256 newBalance) public {
        balance = newBalance;
    }
} 