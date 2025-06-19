// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IFutures {
    function unrealizedPnL() external view returns (int256);
}