// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ZeroAddressVulnerable {
    address public owner;
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Missing zero address check
    function setOwner(address newOwner) public {
        owner = newOwner; // No check for address(0)
    }
    
    // VULNERABLE: Missing zero address check
    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount; // No check for address(0)
    }
    
    // VULNERABLE: Missing zero address check
    function mint(address to, uint256 amount) public {
        balances[to] += amount; // No check for address(0)
    }
    
    // VULNERABLE: Missing zero address check
    function approve(address spender, uint256 amount) public {
        // No check for address(0)
    }
    
    // VULNERABLE: Missing zero address check
    function delegate(address delegatee) public {
        // No check for address(0)
    }
} 