// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FrontRunningVulnerable {
    uint256 public price;
    uint256 public totalSupply;
    
    // VULNERABLE: Front-running in mint function
    function mint() public payable {
        require(msg.value >= price, "Insufficient payment");
        totalSupply += 1;
        // VULNERABLE: No slippage protection
    }
    
    // VULNERABLE: Front-running in swap function
    function swap(uint256 amountIn) public returns (uint256 amountOut) {
        // VULNERABLE: Price calculated from current state
        amountOut = (amountIn * price) / 1e18;
        // VULNERABLE: No deadline or slippage protection
    }
    
    // VULNERABLE: Front-running in claim function
    function claim() public {
        // VULNERABLE: First come, first served
        require(totalSupply < 1000, "All tokens claimed");
        totalSupply += 1;
    }
    
    // VULNERABLE: Front-running in buy function
    function buy() public payable {
        // VULNERABLE: No protection against MEV
        require(msg.value >= price, "Insufficient payment");
        // Process purchase
    }
} 