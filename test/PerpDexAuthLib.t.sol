// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./PerpDexTestBase.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

contract PerpDexAuthLibTest is PerpDexTestBase {
    address[] admins;
    bytes mockSignedData;
    // checkAndLiquidatePosition

    function test_checkUser_validSignature_ethereum() public view {
        string memory message = "Test message";
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", "12", message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PerpDexAuthLib.checkUser(message, 12, signature, user);
    }

    function test_checkUser_validSignature_klaytn() public view {
        string memory message = "Test message";
        bytes32 klaytnSignedMessageHash = keccak256(abi.encodePacked("\x19Klaytn Signed Message:\n", "12", message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, klaytnSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PerpDexAuthLib.checkUser(message, 12, signature, user);
    }

    function test_checkUser_invalidSignature() public {
        string memory message = "Test message";
        bytes memory userSignedData = signMessage(message, userPk2);

        vm.expectRevert("Invalid signed data"); // expected user2 but user
        PerpDexAuthLib.checkUser(message, 12, userSignedData, user);
    }

    function test_setAdmins() public {
        address[] memory newAdmins = new address[](5);
        newAdmins[0] = address(0);
        newAdmins[1] = address(1);
        newAdmins[2] = address(2);
        newAdmins[3] = address(3);
        newAdmins[4] = address(4);

        PerpDexAuthLib._setAdmins(newAdmins, admins);

        assertEq(admins[0], address(0));
        assertEq(admins[1], address(1));
        assertEq(admins[2], address(2));
        assertEq(admins[3], address(3));
        assertEq(admins[4], address(4));
        assertEq(admins.length, 5);

        address[] memory newAdmins2 = new address[](3);
        newAdmins2[0] = address(5);
        newAdmins2[1] = address(6);
        newAdmins2[2] = address(7);
        PerpDexAuthLib._setAdmins(newAdmins2, admins);

        assertEq(admins[0], address(5));
        assertEq(admins[1], address(6));
        assertEq(admins[2], address(7));
        assertEq(admins.length, 3);

        delete admins;
    }

    function test_getSetTpslMsg() public view {
        string memory message = PerpDexAuthLib.getSetTpslMsg(5, 1200, 800, 2, address(12));
        assertEq(
            message,
            string(
                abi.encodePacked(
                    "Set TPSL: ",
                    Strings.toString(5),
                    ", TpPrice: ",
                    Strings.toString(1200),
                    ", SlPrice: ",
                    Strings.toString(800),
                    ", Nonce: ",
                    Strings.toString(2),
                    ", Chain: 8217, Contract: ",
                    Strings.toHexString(address(12))
                )
            )
        );
    }

    function test_getOpenLimitOrderMsg() public view {
        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 1000,
            leverage: 10,
            long: true,
            trader: address(123),
            wantedPrice: 50_000,
            tpPrice: 60_000,
            slPrice: 40_000,
            userSignedData: ""
        });

        string memory message = PerpDexAuthLib.getOpenLimitOrderMsg(o, 5, address(12));
        assertEq(
            message,
            string(
                abi.encodePacked(
                    "Open Limit Order for Token: ",
                    Strings.toString(uint256(o.tokenType)),
                    ", Margin: ",
                    Strings.toString(o.marginAmount),
                    ", Leverage: ",
                    Strings.toString(o.leverage),
                    ", Long: ",
                    Strings.toString(o.long ? 1 : 0),
                    ", Wanted Price: ",
                    Strings.toString(o.wantedPrice),
                    ", TP: ",
                    Strings.toString(o.tpPrice),
                    ", SL: ",
                    Strings.toString(o.slPrice),
                    ", Nonce: ",
                    Strings.toString(5),
                    ", Chain: 8217, Contract: ",
                    Strings.toHexString(address(12))
                )
            )
        );
    }

    function test_getCloseLimitOrderMsg() public view {
        string memory message = PerpDexAuthLib.getCloseLimitOrderMsg(123, 5, address(12));
        assertEq(
            message,
            string(
                abi.encodePacked(
                    "Close Limit Order: ",
                    Strings.toString(123),
                    ", Nonce: ",
                    Strings.toString(5),
                    ", Chain: 8217, Contract: ",
                    Strings.toHexString(address(12))
                )
            )
        );
    }

    function test_getOpenPositionMsg() public view {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        PerpDexLib.OpenPositionData memory o = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 1000,
            leverage: 10,
            long: true,
            trader: address(123),
            expectedPrice: 50_000,
            tpPrice: 60_000,
            slPrice: 40_000,
            userSignedData: "",
            priceData: bisonAIData
        });

        string memory message = PerpDexAuthLib.getOpenPositionMsg(o, 5, address(12));
        assertEq(
            message,
            string(
                abi.encodePacked(
                    "Open position for Token: ",
                    Strings.toString(uint256(o.tokenType)),
                    ", Margin: ",
                    Strings.toString(o.marginAmount),
                    ", Leverage: ",
                    Strings.toString(o.leverage),
                    ", Long: ",
                    Strings.toString(o.long ? 1 : 0),
                    ", TP: ",
                    Strings.toString(o.tpPrice),
                    ", SL: ",
                    Strings.toString(o.slPrice),
                    ", Price: ",
                    Strings.toString(o.expectedPrice),
                    ", Nonce: ",
                    Strings.toString(5),
                    ", Chain: 8217, Contract: ",
                    Strings.toHexString(address(12))
                )
            )
        );
    }
}
