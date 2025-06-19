// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RedundantCodeVulnerable {
    uint256 public value;
    
    // VULNERABLE: Empty function
    function emptyFunction() public {
        // This function does nothing
    }
    
    // VULNERABLE: Dead code
    function deadCode() public {
        if (false) {
            value = 100; // This will never execute
        }
    }
    
    // VULNERABLE: Unreachable code
    function unreachableCode() public {
        return;
        value = 200; // This will never execute
    }
    
    // VULNERABLE: Redundant assignment
    function redundantAssignment() public {
        value = value; // Assigning to itself
    }
    
    // VULNERABLE: Unused parameter
    function unusedParameter(uint256 unused) public {
        // Parameter 'unused' is never used
    }
    
    // VULNERABLE: Unused variable
    function unusedVariable() public {
        uint256 unused = 100; // Variable is never used
    }
} 