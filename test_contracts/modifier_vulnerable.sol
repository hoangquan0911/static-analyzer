// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ModifierVulnerable {
    address public owner;
    bool public paused;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }
    
    // VULNERABLE: Missing onlyOwner modifier
    function withdraw(uint256 amount) public {
        payable(msg.sender).transfer(amount);
    }
    
    // VULNERABLE: Missing whenNotPaused modifier
    function transfer(address to, uint256 amount) public {
        // Transfer logic
    }
    
    // VULNERABLE: Missing onlyOwner modifier
    function setPaused(bool _paused) public {
        paused = _paused;
    }
    
    // VULNERABLE: Missing onlyOwner modifier
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABLE: Missing whenNotPaused modifier
    function mint(address to, uint256 amount) public {
        // Mint logic
    }
} 