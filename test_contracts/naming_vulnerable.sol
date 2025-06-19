// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NamingVulnerable {
    uint256 public x;
    uint256 public y;
    uint256 public z;
    
    // VULNERABLE: Unclear function name
    function func() public {
        // Function does something
    }
    
    // VULNERABLE: Unclear function name
    function test() public {
        // Function does something
    }
    
    // VULNERABLE: Unclear function name
    function temp() public {
        // Function does something
    }
    
    // VULNERABLE: Unclear variable name
    function process() public {
        uint256 a = 100;
        uint256 b = 200;
        uint256 c = a + b;
    }
    
    // VULNERABLE: Unclear parameter name
    function calculate(uint256 x) public {
        // Parameter name is unclear
    }
} 