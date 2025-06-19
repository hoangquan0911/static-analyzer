// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoan {
    function flashLoan(uint256 amount) external;
}

contract FlashLoanVulnerable {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    
    // VULNERABLE: Flash loan without proper validation
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
    
    // VULNERABLE: Flash loan function without checks
    function flashLoan(uint256 amount) external {
        // Transfer tokens to caller
        balanceOf[msg.sender] += amount;
        
        // Call the flash loan callback
        IFlashLoan(msg.sender).flashLoan(amount);
        
        // VULNERABLE: No validation of returned amount
        // Attacker could manipulate state during flash loan
    }
    
    // VULNERABLE: Price manipulation during flash loan
    function getPrice() public view returns (uint256) {
        return totalSupply / 1000; // Simplified price calculation
    }
} 