// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlVulnerable {
    address public owner;
    uint256 public balance;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Missing access control
    function withdraw(uint256 amount) public {
        balance -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // VULNERABLE: Missing access control
    function setBalance(uint256 newBalance) public {
        balance = newBalance;
    }
    
    // VULNERABLE: Missing access control
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABLE: Using tx.origin for authorization
    function adminOnly() public {
        require(tx.origin == owner, "Not authorized");
        // Admin function logic
    }
} 