// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GasLimitVulnerable {
    uint256[] public items;
    
    // VULNERABLE: Unbounded loop
    function processAllItems() public {
        for (uint256 i = 0; i < items.length; i++) {
            // Process each item
            items[i] = items[i] * 2;
        }
    }
    
    // VULNERABLE: Unbounded loop with external calls
    function distributeRewards() public {
        address[] memory users = getUsers();
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
    
    // VULNERABLE: Large array operations
    function addManyItems(uint256[] memory newItems) public {
        for (uint256 i = 0; i < newItems.length; i++) {
            items.push(newItems[i]);
        }
    }
    
    // Helper function
    function getUsers() internal pure returns (address[] memory) {
        // Return large array of users
        address[] memory users = new address[](1000);
        for (uint256 i = 0; i < 1000; i++) {
            users[i] = address(uint160(i));
        }
        return users;
    }
} 