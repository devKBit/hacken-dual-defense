// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../src/LP.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Test, console} from "forge-std/Test.sol";

using SafeERC20 for IERC20;

contract UUPSProxy is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
}

contract LPTest is Test {
    UUPSProxy public lpProxy;
    LP public lp;

    address owner;
    address user;

    function setUp() public {
        (owner,) = makeAddrAndKey("owner");
        (user,) = makeAddrAndKey("user");

        vm.startPrank(owner);

        LP lpImpl = new LP();
        lpProxy = new UUPSProxy(address(lpImpl), "");
        lp = LP(address(lpProxy));
        lp.initialize(owner, address(0x1), address(0x2));

        vm.stopPrank();
    }

    function test_giveProfit() public {
        vm.expectRevert("Only perpDex contract can give profit");
        lp.giveProfit(user, 100);

        vm.startPrank(address(lp.perpDex()));
        vm.mockCall(address(lp.usdt()), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        vm.expectCall(address(lp.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, user, 100), 1);
        lp.giveProfit(user, 100);
    }
}
