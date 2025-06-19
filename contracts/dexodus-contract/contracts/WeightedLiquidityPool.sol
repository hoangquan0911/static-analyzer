// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {UUPSUpgradeable} from "../upgradeable/UUPSUpgradeable.sol";
import {ERC20Upgradeable} from "../upgradeable/ERC20Upgradeable.sol";
import {Ownable2StepUpgradeable} from "../upgradeable/Ownable2StepUpgradeable.sol";
import {SafeERC20, IERC20} from "../libraries/SafeERC20.sol";
import {IV3SwapRouter} from "../interfaces/IV3SwapRouter.sol";
import {IWETH9} from "../interfaces/IWETH9.sol";
import {AggregatorV3Interface} from "../interfaces/AggregatorV3Interface.sol";
import {IFutures} from "../interfaces/IFutures.sol";

/**
 * @title WeightedLiquidityPool
 * @dev This contract is the unique liquidity pool for all perpetual markets on the Dexodus platform.
 * It manages liquidity contributed in native ETH, which is wrapped into WETH upon deposit and then
 * rebalanced to maintain a target weighting between WETH and USDC in USD value.
 *
 * Key Features:
 * - Accepts native ETH for liquidity provisioning, which is automatically wrapped to WETH upon deposit.
 * - Allows liquidity providers to lock their liquidity with specific "animal" tiers representing different
 *   locked amounts and durations, while also supporting non-locked liquidity for flexible deposits.
 * - Rebalances pool liquidity periodically between WETH and USDC to maintain a target weight in USD terms,
 *   ensuring adequate exposure and stability in the pool value.
 * - Facilitates payout in USDC for traders realizing a positive profit and loss (PnL) when closing positions,
 *   automatically converting WETH to USDC when necessary.
 * - Enforces strict control over pool token transfers, where tokens can only be minted or burned by the contract,
 *   maintaining liquidity integrity within the pool.
 *
 * Rebalancing Strategy:
 * - The pool monitors its WETH and USDC balances and periodically adjusts based on set weights for WETH and USDC.
 * - Excess assets are swapped to reach the target USD distribution, optimizing liquidity availability
 *   and stability for Dexodus perpetual markets.
 *
 * Security Measures:
 * - Ensures only authorized contracts, such as the FuturesCore, can perform specific operations like USDC payouts.
 * - Uses OpenZeppelin upgradeable libraries for UUPS upgradeability and safe token handling.
 *
 * This unique design aims to provide a robust, flexible, and secure liquidity foundation for all Dexodus
 * perpetual markets, with built-in rebalancing to optimize exposure and pool stability.
 */
contract WeightedLiquidityPool is
    UUPSUpgradeable,
    ERC20Upgradeable,
    Ownable2StepUpgradeable
{
    using SafeERC20 for IERC20;

    uint256 constant BASIS_POINTS = 10_000;

    address public futuresCore;

    IERC20 public USDC;
    IWETH9 public WETH;
    IV3SwapRouter public uniswapRouter;
    AggregatorV3Interface public priceFeed;

    uint8 public priceFeedDecimals;

    uint256 lockLiqAvailable;
    uint256 addLiqAvailable;

    struct LockedLiquidity {
        uint256 amount;
        uint256 unlockTime;
        AnimalType animalType;
    }

    mapping(address => LockedLiquidity[]) public lockedLiquidity;

    mapping(address => uint256) public nonLockedLiquidity;

    uint256 public swapSlippage;

    enum AnimalType { Crab, Octopus, Fish, Dolphin, Shark, Whale }

    event AddedLiquidity(address indexed lp, uint256 ethAmount, uint256 ethValueInUSD);
    event WithdrawedLiquidity(address indexed lp, uint256 wethOut);
    event LockedLiquidityExecuted(
        address indexed lp,
        uint256 indexed id,
        uint256 ethAmount,
        uint256 ethValueInUSD,
        AnimalType animalType,
        uint256 lockPeriod,
        uint256 unlockTime
    );
    event UnLockedLiquidityExecuted(address indexed lp, uint256 indexed id, uint256 wethOut);
    event PoolRebalanced(uint256 newEthBalance, uint256 newUsdcBalance);

    struct LockedLiquidityExtraAnimals {
        uint256 amount;
        uint256 unlockTime;
        uint256 animalType;
    }

    // animal number (using from 6(included) and above) => how much it costs (in USD value)
    mapping(uint256 => uint256) public trackExtraAnimals;

    mapping(address => LockedLiquidityExtraAnimals[]) public lockedLiquidityExtraAnimals;

    event LockedLiquidityExecutedExtraAnimals(
        address indexed lp,
        uint256 indexed id,
        uint256 ethAmount,
        uint256 ethValueInUSD,
        uint256 animalType,
        uint256 lockPeriod,
        uint256 unlockTime
    );
    event UnLockedLiquidityExecutedExtraAnimals(address indexed lp, uint256 indexed id, uint256 wethOut);

    // new features --------------------------------------------------------------

    struct LockedLiquidityAny {
        uint256 amount;
        uint256 unlockTime;
    }

    mapping(address => LockedLiquidityAny[]) public lockedLiquidityAny;

    event LockedLiquidityExecutedAny(
        address indexed lp,
        uint256 indexed id,
        uint256 ethAmount,
        uint256 ethValueInUSD,
        uint256 lpAmountOut,
        uint256 lockPeriod,
        uint256 unlockTime
    );

    event UnLockedLiquidityExecutedAny(address indexed lp, uint256 indexed id, uint256 wethOut, uint256 amountToUnlock);

    // ---------------------------------------------------------------------------

    modifier onlyFuturesCore() {
        require(msg.sender == futuresCore, "Only callable by the futuresCore contract");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _usdc,
        address _weth,
        string memory _name,
        string memory _symbol,
        address _uniswapRouter,
        address _priceFeed
    ) external initializer {
        __UUPSUpgradeable_init();
        __Ownable2Step_init();
        __ERC20_init(_name, _symbol);
        _transferOwnership(msg.sender);

        require(_usdc != address(0), "Invalid address");
        require(_weth != address(0), "Invalid address");
        require(_uniswapRouter != address(0), "Invalid address");
        require(_priceFeed != address(0), "Invalid address");

        USDC = IERC20(_usdc);
        WETH = IWETH9(_weth);
        uniswapRouter = IV3SwapRouter(_uniswapRouter);
        priceFeed = AggregatorV3Interface(_priceFeed);
        priceFeedDecimals = priceFeed.decimals();
    }

    /**
     * @dev Sets the address of the FuturesCore contract, which is authorized to call certain restricted functions.
     * @param _futuresCore The address of the FuturesCore contract.
     */
    function setFuturesCore(address _futuresCore) external onlyOwner {
        require(_futuresCore != address(0), "Invalid address");
        futuresCore = _futuresCore;
    }

    /**
     * @dev Sets the address of the ETH/USD PriceFeed contract.
     * @param _priceFeed The address of the PriceFeed contract.
     */
    function setPriceFeed(address _priceFeed) external onlyOwner {
        require(_priceFeed != address(0), "Invalid address");
        priceFeed = AggregatorV3Interface(_priceFeed);
        priceFeedDecimals = priceFeed.decimals();
    }

    /**
     * @dev Controls the availability of liquidity locking.
     * @param x Value to set lockLiqAvailable to 0 or 1.
     */
    function setlLockLiqAvailable(uint256 x) external onlyOwner {
        lockLiqAvailable = x;
    }

    /**
     * @dev Controls the availability of adding liquidity.
     * @param x Value to set addLiqAvailable to 0 or 1.
     */
    function setAddLiqAvailable(uint256 x) external onlyOwner {
        addLiqAvailable = x;
    }

    /**
     * @dev Set the % of slippage accepted during token swaps.
     * @param slippage Value to set swapSlippage to the % accepted.
     */
    function setSwapSlippage(uint256 slippage) external onlyOwner {
        require(slippage <= BASIS_POINTS, "Slippage exceeds allowable range");
        swapSlippage = slippage; // set to 0.1% by default => slippage == 10
    }

    /**
     * @dev Add a new animal type to lock into the liquidity pool.
     * @param animal New animal number to lock into the liquidity pool.
     * @param usdAmount How much the animal costs in usd value.
     */
    function addNewAnimalType(uint256 animal, uint256 usdAmount) external onlyOwner {
        require(animal > 5, "Invalid animal id");
        require(usdAmount > 0, "USD cost must be higher than 0");
        trackExtraAnimals[animal] = usdAmount;
    }

    /**
     * @dev Allows an LP to lock liquidity in the pool for a specified period with a designated animal tier.
     * @param months Duration of the lock in months (valid values: 4, 6, or 8 months).
     * @param animalType A type indicating the liquidity tier (e.g., "Crab", "Octopus", etc.).
     */
    function lockLiquidity(uint256 months, AnimalType animalType) external payable {
        require(lockLiqAvailable == 1, "Only callable when available");
        require(msg.value > 0, "ETH amount must be greater than 0");
        require(months == 4 || months == 6 || months == 8, "Invalid lock period");

        uint256 ethValueInUSD = getEthPriceInUSD(msg.value);
        require(
            (animalType == AnimalType.Crab && ethValueInUSD >= 100e6) ||
            (animalType == AnimalType.Octopus && ethValueInUSD >= 500e6) ||
            (animalType == AnimalType.Fish && ethValueInUSD >= 2_500e6) ||
            (animalType == AnimalType.Dolphin && ethValueInUSD >= 10_000e6) ||
            (animalType == AnimalType.Shark && ethValueInUSD >= 25_000e6) ||
            (animalType == AnimalType.Whale && ethValueInUSD >= 100_000e6),
            "Invalid animal type or insufficient ETH value"
        );

        uint256 lpAmountOut = calcLpOut(ethValueInUSD);
        require(lpAmountOut > 0, "Low lpAmountOut");
        WETH.deposit{value: msg.value}();

        uint256 id = lockedLiquidity[msg.sender].length;

        lockedLiquidity[msg.sender].push(LockedLiquidity({
            amount: lpAmountOut,
            unlockTime: block.timestamp + (months * 30 days),
            animalType: animalType
        }));

        _mint(msg.sender, lpAmountOut);
        emit LockedLiquidityExecuted(msg.sender, id, msg.value, ethValueInUSD, animalType, months, block.timestamp + (months * 30 days));
    }

    /**
     * @dev Allows an LP to lock liquidity in the pool for a specified period with a designated animal tier.
     * @param months Duration of the lock in months (valid values: 4, 6, or 8 months).
     * @param animalType A type number indicating the liquidity tier (e.g., "Crab", "Octopus", etc.).
     */
    function lockLiquidityExtraAnimals(uint256 months, uint256 animalType) external payable {
        require(lockLiqAvailable == 1, "Only callable when available");
        require(msg.value > 0, "ETH amount must be greater than 0");
        require(months == 4 || months == 6 || months == 8, "Invalid lock period");

        uint256 ethValueInUSD = getEthPriceInUSD(msg.value);
        require(trackExtraAnimals[animalType] != 0, "Invalid animal type");
        require(ethValueInUSD >= trackExtraAnimals[animalType], "Insufficient ETH value");

        uint256 lpAmountOut = calcLpOut(ethValueInUSD);
        require(lpAmountOut > 0, "Low lpAmountOut");
        WETH.deposit{value: msg.value}();

        uint256 id = lockedLiquidityExtraAnimals[msg.sender].length;

        lockedLiquidityExtraAnimals[msg.sender].push(LockedLiquidityExtraAnimals({
            amount: lpAmountOut,
            unlockTime: block.timestamp + (months * 30 days),
            animalType: animalType
        }));

        _mint(msg.sender, lpAmountOut);
        emit LockedLiquidityExecutedExtraAnimals(msg.sender, id, msg.value, ethValueInUSD, animalType, months, block.timestamp + (months * 30 days));
    }

    /**
     * @dev Allows an LP to lock liquidity in the pool for a specified period with a desired amount of ETH.
     * @param day Duration of the lock in days.
     */
    function lockLiquidityAny(uint256 day) external payable {
        require(addLiqAvailable == 1, "Only callable when available");
        require(msg.value > 0, "ETH amount must be greater than 0");

        uint256 ethValueInUSD = getEthPriceInUSD(msg.value);

        uint256 lpAmountOut = calcLpOut(ethValueInUSD);
        require(lpAmountOut > 0, "Low lpAmountOut");
        WETH.deposit{value: msg.value}();

        uint256 id = lockedLiquidityAny[msg.sender].length;

        lockedLiquidityAny[msg.sender].push(LockedLiquidityAny({
            amount: lpAmountOut,
            unlockTime: block.timestamp + (day * 1 days)
        }));

        _mint(msg.sender, lpAmountOut);
        emit LockedLiquidityExecutedAny(msg.sender, id, msg.value, ethValueInUSD, lpAmountOut, day, block.timestamp + (day * 1 days));
    }

    /**
     * @dev Allows an LP to unlock previously locked liquidity once the lock period has expired.
     * @param id The identifier of the locked liquidity entry to unlock.
     * @param amountToUnlock The amount lp wants to unlock from position id.
     */
    function unlockLiquidityAny(uint256 id, uint256 amountToUnlock) external {
        require(id < lockedLiquidityAny[msg.sender].length, "Invalid unlock ID");
        LockedLiquidityAny storage userLock = lockedLiquidityAny[msg.sender][id];
        uint256 lpAmount = userLock.amount;
        require(lpAmount >= amountToUnlock && amountToUnlock > 0, "Insufficient locked liquidity");
        require(userLock.unlockTime <= block.timestamp, "Not unlocked yet");  

        userLock.amount -= amountToUnlock;

        uint256 wethOut = calcEthOut(amountToUnlock);

        uint256 wethBalance = WETH.balanceOf(address(this));

        if (wethBalance < wethOut) {
            uint256 shortfall = wethOut - wethBalance;
            _swapUsdcToEthExactOutput(shortfall);
        }

        WETH.withdraw(wethOut);

        _burn(msg.sender, amountToUnlock);
        
        (bool success, ) = msg.sender.call{value: wethOut}("");
        require(success, "ETH transfer failed");

        emit UnLockedLiquidityExecutedAny(msg.sender, id, wethOut, amountToUnlock);
    }

    /**
     * @dev Allows an LP to unlock previously locked liquidity once the lock period has expired.
     * @param id The identifier of the locked liquidity entry to unlock.
     */
    function unlockLiquidity(uint256 id) external {
        require(id < lockedLiquidity[msg.sender].length, "Invalid unlock ID");
        LockedLiquidity storage userLock = lockedLiquidity[msg.sender][id];
        uint256 lpAmount = userLock.amount;
        require(lpAmount > 0, "No locked liquidity found");
        require(userLock.unlockTime <= block.timestamp, "Not unlocked yet");  

        userLock.amount = 0;

        uint256 wethOut = calcEthOut(lpAmount);

        uint256 wethBalance = WETH.balanceOf(address(this));

        if (wethBalance < wethOut) {
            uint256 shortfall = wethOut - wethBalance;
            _swapUsdcToEthExactOutput(shortfall);
        }

        WETH.withdraw(wethOut);

        _burn(msg.sender, lpAmount);
        
        (bool success, ) = msg.sender.call{value: wethOut}("");
        require(success, "ETH transfer failed");

        emit UnLockedLiquidityExecuted(msg.sender, id, wethOut);
    }

    /**
     * @dev Allows an LP to unlock previously locked liquidity once the lock period has expired.
     * @param id The identifier of the locked liquidity entry to unlock.
     */
    function unlockLiquidityExtraAnimals(uint256 id) external {
        require(id < lockedLiquidityExtraAnimals[msg.sender].length, "Invalid unlock ID");
        LockedLiquidityExtraAnimals storage userLock = lockedLiquidityExtraAnimals[msg.sender][id];
        uint256 lpAmount = userLock.amount;
        require(lpAmount > 0, "No locked liquidity found");
        require(userLock.unlockTime <= block.timestamp, "Not unlocked yet");  

        userLock.amount = 0;

        uint256 wethOut = calcEthOut(lpAmount);

        uint256 wethBalance = WETH.balanceOf(address(this));

        if (wethBalance < wethOut) {
            uint256 shortfall = wethOut - wethBalance;
            _swapUsdcToEthExactOutput(shortfall);
        }

        WETH.withdraw(wethOut);

        _burn(msg.sender, lpAmount);
        
        (bool success, ) = msg.sender.call{value: wethOut}("");
        require(success, "ETH transfer failed");

        emit UnLockedLiquidityExecutedExtraAnimals(msg.sender, id, wethOut);
    }

    /**
     * @dev Allows an LP to add non-locked liquidity to the pool.
     * The added liquidity is minted as pool tokens to represent the LP's share.
     */
    function addLiquidity() external payable {
        require(addLiqAvailable == 1, "Only callable when available");
        require(msg.value > 0, "ETH amount must be greater than 0");

        uint256 ethValueInUSD = getEthPriceInUSD(msg.value);
        uint256 lpAmountOut = calcLpOut(ethValueInUSD);
        require(lpAmountOut > 0, "Low lpAmountOut");
        WETH.deposit{value: msg.value}();

        _mint(msg.sender, lpAmountOut);
        nonLockedLiquidity[msg.sender] += lpAmountOut;
        emit AddedLiquidity(msg.sender, msg.value, ethValueInUSD);
    }

    /**
     * @dev Allows an LP to withdraw non-locked liquidity from the pool by burning pool tokens.
     * If insufficient WETH is held in the contract, USDC is swapped to WETH to meet the withdrawal amount.
     * @param lpAmount The amount of LP tokens to burn and withdraw equivalent WETH.
     */
    function withdrawLiquidity(uint256 lpAmount) external {
        require(lpAmount > 0, "LP amount must be greater than 0");
        require(lpAmount <= nonLockedLiquidity[msg.sender], "Insufficient LP balance");
        
        uint256 wethOut = calcEthOut(lpAmount);

        uint256 wethBalance = WETH.balanceOf(address(this));

        if (wethBalance < wethOut) {
            uint256 shortfall = wethOut - wethBalance;
            _swapUsdcToEthExactOutput(shortfall);
        }

        WETH.withdraw(wethOut);
        
        _burn(msg.sender, lpAmount);
        nonLockedLiquidity[msg.sender] -= lpAmount;

        (bool success, ) = msg.sender.call{value: wethOut}("");
        require(success, "ETH transfer failed");

        emit WithdrawedLiquidity(msg.sender, wethOut);
    }

    /**
     * @dev Pays out positive PnL in USDC to a trader closing a profitable position.
     * If insufficient USDC is held, swaps WETH to meet the amount.
     * @param trader Address of the trader receiving the payout.
     * @param usdcAmount The amount of USDC to transfer.
     */
    function payOutUSDC(address trader, uint256 usdcAmount) external onlyFuturesCore {
        uint256 usdcBalance = USDC.balanceOf(address(this));

        if (usdcBalance < usdcAmount) {
            uint256 shortfall = usdcAmount - usdcBalance;
            _swapEthToUsdcExactOutput(shortfall);
        }

        USDC.safeTransfer(trader, usdcAmount);
    }

    /**
     * @dev Rebalances the pool to maintain a target distribution between WETH and USDC.
     * Executed periodically, typically every 4 hours.
     * @param eth_WEIGHT Target percentage for WETH in the pool.
     * @param usdc_WEIGHT Target percentage for USDC in the pool.
     */
    function rebalancePool(uint256 eth_WEIGHT, uint256 usdc_WEIGHT) external onlyOwner {
        require(eth_WEIGHT + usdc_WEIGHT == 100, "Incorrect weights");
        uint256 wethBalance = WETH.balanceOf(address(this));
        uint256 usdcBalance = USDC.balanceOf(address(this));
        uint256 totalValueInUSD = wethBalance * getEthPriceInUSD(1 ether) / 1e6 + (usdcBalance * 1e18 / 1e6);

        if (totalValueInUSD > 0) {
            uint256 targetWethValue = (totalValueInUSD * eth_WEIGHT) / 100;
            uint256 targetUsdcValue = (totalValueInUSD * usdc_WEIGHT) / 100;

            if (wethBalance * getEthPriceInUSD(1 ether) / 1e6 > targetWethValue) {
                uint256 excessWeth = (wethBalance * getEthPriceInUSD(1 ether) / 1e6 - targetWethValue) * 1e6 / getEthPriceInUSD(1 ether);
                _swapEthToUsdc(excessWeth);
            } else if (usdcBalance * 1e18 / 1e6 > targetUsdcValue) {
                uint256 excessUsdc = usdcBalance - (targetUsdcValue * 1e6 / 1e18);
                _swapUsdcToEth(excessUsdc);
            }

            emit PoolRebalanced(targetWethValue, targetUsdcValue);
        }
    }

    /**
     * @dev Executes a swap from WETH to USDC to reach an exact USDC output amount.
     * @param usdcAmountOut The exact amount of USDC desired as output from the swap.
     */
    function _swapEthToUsdcExactOutput(uint256 usdcAmountOut) internal {
        uint256 ethPriceInUsd = getEthPriceInUSD(1 ether);
        uint256 maxEthIn = (usdcAmountOut * 1e18) / ethPriceInUsd;

        maxEthIn += maxEthIn * swapSlippage / BASIS_POINTS;

        WETH.approve(address(uniswapRouter), maxEthIn);

        uniswapRouter.exactOutputSingle(
            IV3SwapRouter.ExactOutputSingleParams({
                tokenIn: address(WETH),
                tokenOut: address(USDC),
                fee: 500,
                recipient: address(this),
                amountOut: usdcAmountOut,
                amountInMaximum: maxEthIn,
                sqrtPriceLimitX96: 0
            })
        );

        WETH.approve(address(uniswapRouter), 0);
    }

    /**
     * @dev Executes a swap from USDC to WETH to reach an exact WETH output amount.
     * @param wethAmountOut The exact amount of WETH desired as output from the swap.
     */
    function _swapUsdcToEthExactOutput(uint256 wethAmountOut) internal {
        uint256 ethPriceInUsd = getEthPriceInUSD(1 ether);
        uint256 maxUsdcIn = (wethAmountOut * ethPriceInUsd) / 1e18;

        maxUsdcIn += maxUsdcIn * swapSlippage / BASIS_POINTS;

        USDC.approve(address(uniswapRouter), maxUsdcIn);

        uniswapRouter.exactOutputSingle(
            IV3SwapRouter.ExactOutputSingleParams({
                tokenIn: address(USDC),
                tokenOut: address(WETH),
                fee: 500,
                recipient: address(this),
                amountOut: wethAmountOut,
                amountInMaximum: maxUsdcIn,
                sqrtPriceLimitX96: 0
            })
        );

        USDC.approve(address(uniswapRouter), 0);
    }

    /**
     * @dev Executes a swap from WETH to USDC for a specific input amount of WETH.
     * @param wethAmount Amount of WETH to swap into USDC.
     */
    function _swapEthToUsdc(uint256 wethAmount) internal {
        WETH.approve(address(uniswapRouter), wethAmount);

        uint256 ethPriceInUsd = getEthPriceInUSD(1 ether);
        uint256 minUsdcOut = (wethAmount * ethPriceInUsd) / 1e18;

        minUsdcOut -= minUsdcOut * swapSlippage / BASIS_POINTS;

        uniswapRouter.exactInputSingle(
            IV3SwapRouter.ExactInputSingleParams({
                tokenIn: address(WETH),
                tokenOut: address(USDC),
                fee: 500,
                recipient: address(this),
                amountIn: wethAmount,
                amountOutMinimum: minUsdcOut,
                sqrtPriceLimitX96: 0
            })
        );
    }

    /**
     * @dev Executes a swap from USDC to WETH for a specific input amount of USDC.
     * @param usdcAmount Amount of USDC to swap into WETH.
     */
    function _swapUsdcToEth(uint256 usdcAmount) internal {
        USDC.approve(address(uniswapRouter), usdcAmount);

        uint256 ethPriceInUsd = getEthPriceInUSD(1 ether);
        uint256 minWethOut = (usdcAmount * 1e18) / ethPriceInUsd;

        minWethOut -= minWethOut * swapSlippage / BASIS_POINTS;

        uniswapRouter.exactInputSingle(
            IV3SwapRouter.ExactInputSingleParams({
                tokenIn: address(USDC),
                tokenOut: address(WETH),
                fee: 500,
                recipient: address(this),
                amountIn: usdcAmount,
                amountOutMinimum: minWethOut,
                sqrtPriceLimitX96: 0
            })
        );
    }

    /**
     * @dev Calculates the effective pool value in USD by combining WETH and USDC balances.
     * Includes adjustments for unrealized PnL from FuturesCore if set.
     * Returns totalValueInUSD as 18 decimal value
     * @return totalValueInUSD Total effective value of the pool in USD.
     */
    function getEffectivePoolValue() public view returns (uint256 totalValueInUSD) {
        uint256 wethBalance = WETH.balanceOf(address(this));
        uint256 usdcBalance = USDC.balanceOf(address(this));

        totalValueInUSD = wethBalance * getEthPriceInUSD(1 ether) / 1e6 + (usdcBalance * 1e18 / 1e6);

        if (futuresCore != address(0)) {
            int256 unrealizedPnL = IFutures(futuresCore).unrealizedPnL();
            unrealizedPnL = (unrealizedPnL * 1e18 / 1e6);

            if (unrealizedPnL >= 0 && uint256(unrealizedPnL) > totalValueInUSD) {
                return 0;
            }

            if (unrealizedPnL >= 0) {
                totalValueInUSD = totalValueInUSD - uint256(unrealizedPnL);
            } else {
                totalValueInUSD = totalValueInUSD + uint256(-unrealizedPnL);
            }
        }
    }

    /**
     * @dev Calculates the amount of WETH equivalent to a specified number of LP tokens.
     * Receives lpAmount as 18 decimal value and returns wethOut as 18 decimal value
     * @param lpAmount The amount of LP tokens to convert into WETH.
     * @return wethOut Amount of WETH equivalent to the LP tokens provided.
     */
    function calcEthOut(uint256 lpAmount) public view returns (uint256 wethOut) {
        if (totalSupply() == 0) return 0;
        uint256 totalValueInUSD = getEffectivePoolValue();

        uint256 fraction = (lpAmount * 1e18) / totalSupply();

        wethOut = (totalValueInUSD * fraction) / (getEthPriceInUSD(1 ether) * 1e18 / 1e6);
    }

    /**
     * @dev Calculates the LP tokens that should be minted for a specified USD value in WETH.
     * Receives wethValueInUSD as 6 decimal value and returns lpOut as 18 decimal value
     * Minimum totalValueInUSD is $10. Ensures the pool value is not below the minimum threshold
     * @param wethValueInUSD The USD value in WETH to convert into LP tokens.
     * @return lpOut Number of LP tokens to mint.
     */
    function calcLpOut(uint256 wethValueInUSD) public view returns (uint256 lpOut) {
        uint256 totalValueInUSD = getEffectivePoolValue();

        if (totalValueInUSD < 10e18) {
            totalValueInUSD = 10e18;
        }

        if (totalSupply() == 0) {
            lpOut = wethValueInUSD * 1e18 / 1e6;
        } else {
            lpOut = (wethValueInUSD * 1e18 / 1e6) * totalSupply() / totalValueInUSD;
        }
    }

    /**
     * @dev Fetches the current ETH/USD price from the Chainlink oracle.
     * Receives ethAmount as 18 decimal value and returns the price as 6 decimal value
     * @param ethAmount The amount of ETH to evaluate.
     * @return USD value equivalent for the specified ETH amount.
     */
    function getEthPriceInUSD(uint256 ethAmount) public view returns (uint256) {
        (
            , // roundId
            int256 price,
            , // startedAt
            uint256 timestamp,
            // answeredInRound
        ) = priceFeed.latestRoundData();

        require(price > 0, "Invalid price from oracle");

        require(block.timestamp - timestamp <= 1 hours, "Stale price data");

        uint256 adjustedPrice;
        if (18 < priceFeedDecimals) {
            uint256 difference = priceFeedDecimals - 18;
            adjustedPrice = uint256(price) / 10 ** difference;
        } else {
            uint256 difference = 18 - priceFeedDecimals;
            adjustedPrice = uint256(price) * 10 ** difference;
        }

        return (ethAmount * adjustedPrice) / 1e18 / 1e12;
    }

    /**
     * @dev Disables direct transfers of pool tokens to maintain liquidity pool integrity.
     */
    function transfer(address to, uint256 value) public override returns (bool){
        revert("Token transfers are not allowed");
    }

    /**
     * @dev Disables direct transfers from other addresses, enforcing controlled pool token flow.
     */
    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        revert("Token transfers are not allowed");
    }

    receive() external payable {}

    function version() external pure returns (uint256) {
        return 1;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    uint256[50] private __gap;
}